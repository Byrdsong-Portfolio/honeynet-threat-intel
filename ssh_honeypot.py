#!/usr/bin/env python3
"""
SSH Honeypot — listens on port 2222 and emulates OpenSSH 7.4.

For every inbound connection it:
  1. Completes the SSH handshake (Paramiko transport)
  2. Accepts any username/password and logs the credential pair
  3. Opens a fake interactive shell that logs every command typed
  4. Returns a plausible fake prompt then kills the session

Run:
    python3 ssh_honeypot.py [--host 0.0.0.0] [--port 2222]
"""

import argparse
import logging
import socket
import sys
import threading
import uuid
from pathlib import Path

import paramiko
from dotenv import load_dotenv

load_dotenv()

# ── project imports ───────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import log_event
from utils.geoip import resolve
from utils.alerting import notify, validate_webhook

# ── Paramiko logging ──────────────────────────────────────────────────────────
logging.getLogger("paramiko").setLevel(logging.WARNING)

HOST_KEY_PATH = Path("ssh_host_rsa_key")


def _get_host_key() -> paramiko.RSAKey:
    if HOST_KEY_PATH.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_PATH))
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_PATH))
    return key


HOST_KEY = _get_host_key()

# Fake banner — looks like a real Ubuntu box
BANNER = "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7"

# Commands that get a realistic-ish response
FAKE_RESPONSES: dict[str, str] = {
    "id":        "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "whoami":    "root\r\n",
    "uname -a":  "Linux ubuntu 4.9.0-8-amd64 #1 SMP Debian 4.9.130-2 (2018-10-27) x86_64 GNU/Linux\r\n",
    "uname":     "Linux\r\n",
    "pwd":       "/root\r\n",
    "ls":        "snap\r\n",
    "ls -la":    "total 28\r\ndrwx------ 3 root root 4096 Jan  1 00:00 .\r\ndrwxr-xr-x 18 root root 4096 Jan  1 00:00 ..\r\ndrwxr-xr-x 3 root root 4096 Jan  1 00:00 snap\r\n",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\r\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n",
    "history":   "    1  ls\r\n    2  id\r\n",
    "hostname":  "ubuntu\r\n",
    "ifconfig":  "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n        inet 10.0.0.2\r\n",
    "ip addr":   "1: lo: <LOOPBACK,UP>\r\n2: eth0: <BROADCAST,MULTICAST,UP>\r\n    inet 10.0.0.2/24\r\n",
    "exit":      "",
    "quit":      "",
}


class HoneypotInterface(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int):
        self.client_ip   = client_ip
        self.client_port = client_port
        self.session_id  = uuid.uuid4().hex[:12]
        self.username    = ""
        self.password    = ""
        self.event       = threading.Event()

    # Always allow password auth — capture credentials; log/alert after
    # transport.start_server() returns so client_version is populated.
    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username
        self.password = password
        self.geo = resolve(self.client_ip)
        print(f"[ssh] {self.client_ip} → user={username!r} pass={password!r} [{self.geo.get('country','??')}]")
        return paramiko.AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        cmd = command.decode(errors="replace").strip()
        _log_command(self.session_id, self.client_ip, cmd)
        resp = FAKE_RESPONSES.get(cmd, f"bash: {cmd}: command not found\r\n")
        channel.send(resp)
        channel.send_exit_status(0)
        return True


def _log_command(session_id: str, ip: str, command: str) -> None:
    log_event("ssh_cmd", {
        "source_ip":  ip,
        "session_id": session_id,
        "command":    command,
    })
    print(f"[ssh_cmd] {ip} → {command!r}")


def _handle_shell(channel: paramiko.Channel, iface: HoneypotInterface) -> None:
    """Drive the fake interactive shell for one session."""
    prompt = b"root@ubuntu:~# "
    channel.send(b"\r\nWelcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.9.0-8-amd64 x86_64)\r\n\r\n")
    channel.send(prompt)

    buf = b""
    while True:
        try:
            data = channel.recv(1024)
        except Exception:
            break
        if not data:
            break

        buf += data
        channel.send(data)  # echo

        while b"\r" in buf or b"\n" in buf:
            for delim in (b"\r\n", b"\r", b"\n"):
                idx = buf.find(delim)
                if idx >= 0:
                    cmd = buf[:idx].decode(errors="replace").strip()
                    buf = buf[idx + len(delim):]
                    if cmd:
                        _log_command(iface.session_id, iface.client_ip, cmd)
                    if cmd.lower() in ("exit", "quit", "logout"):
                        channel.send(b"\r\nlogout\r\n")
                        channel.close()
                        return
                    resp = FAKE_RESPONSES.get(cmd, f"bash: {cmd}: command not found\r\n")
                    channel.send(("\r\n" + resp).encode())
                    channel.send(prompt)
                    break
            else:
                break

    channel.close()


def _handle_client(conn: socket.socket, addr: tuple) -> None:
    ip, port = addr[0], addr[1]
    transport: paramiko.Transport | None = None
    try:
        transport = paramiko.Transport(conn)
        transport.local_version = BANNER
        transport.add_server_key(HOST_KEY)

        iface = HoneypotInterface(ip, port)

        # Sniff the client version string right after SSH header exchange
        try:
            transport.start_server(server=iface)
        except paramiko.SSHException:
            return

        iface._client_version = transport.remote_version or "unknown"

        # Log and alert here so client_version is the real value, not "unknown".
        if iface.username:
            ev = {
                "source_ip":      iface.client_ip,
                "source_port":    iface.client_port,
                "geo":            getattr(iface, "geo", {}),
                "username":       iface.username,
                "password":       iface.password,
                "client_version": iface._client_version,
                "session_id":     iface.session_id,
            }
            log_event("ssh", ev)
            notify("ssh", ev)

        channel = transport.accept(30)
        if channel is None:
            return

        iface.event.wait(10)
        if not iface.event.is_set():
            return

        _handle_shell(channel, iface)

    except Exception as exc:
        print(f"[ssh] Error from {ip}: {exc}")
    finally:
        if transport:
            transport.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=2222)
    args = parser.parse_args()

    validate_webhook()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(128)
    print(f"[ssh] Listening on {args.host}:{args.port}")

    while True:
        try:
            conn, addr = sock.accept()
            t = threading.Thread(target=_handle_client, args=(conn, addr), daemon=True)
            t.start()
        except KeyboardInterrupt:
            print("\n[ssh] Shutting down.")
            break
        except Exception as exc:
            print(f"[ssh] Accept error: {exc}")


if __name__ == "__main__":
    main()
