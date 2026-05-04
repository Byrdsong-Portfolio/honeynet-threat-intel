#!/usr/bin/env python3
"""
MySQL Honeypot — raw socket server on port 3306.

Completes the MySQL 5.7 client handshake, captures the auth attempt
(username, auth plugin, capability flags, client version string),
then returns ERR_ACCESS_DENIED.

Does NOT execute any SQL. This is purely a handshake-level listener.

Run:
    python3 mysql_honeypot.py [--host 0.0.0.0] [--port 3306]
"""

import argparse
import os
import socket
import struct
import sys
import threading
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from utils.logger import log_event
from utils.geoip import resolve
from utils.alerting import notify

# ── MySQL wire protocol helpers ───────────────────────────────────────────────

def _packet(seq: int, payload: bytes) -> bytes:
    """Wrap payload in a MySQL packet header (3-byte length + 1-byte seq)."""
    return struct.pack("<I", len(payload))[:3] + bytes([seq]) + payload


def _handshake_v10() -> bytes:
    """
    Build a MySQL 5.7 Server Greeting (HandshakeV10) packet.
    Enough to make real MySQL clients attempt authentication.
    """
    protocol_version = b"\x0a"            # 10
    server_version   = b"5.7.38-log\x00"
    connection_id    = struct.pack("<I", 1)
    auth_plugin_data_1 = os.urandom(8)    # first 8 bytes of auth challenge
    filler           = b"\x00"
    capability_lower = struct.pack("<H", 0xF7FF)  # common cap flags
    charset          = b"\x21"            # utf8
    status_flags     = struct.pack("<H", 0x0002)
    capability_upper = struct.pack("<H", 0x81FF)
    auth_plugin_len  = struct.pack("B", 21)       # len of full auth data
    reserved         = b"\x00" * 10
    auth_plugin_data_2 = os.urandom(12) + b"\x00"
    auth_plugin_name = b"mysql_native_password\x00"

    payload = (
        protocol_version
        + server_version
        + connection_id
        + auth_plugin_data_1
        + filler
        + capability_lower
        + charset
        + status_flags
        + capability_upper
        + auth_plugin_len
        + reserved
        + auth_plugin_data_2
        + auth_plugin_name
    )
    return _packet(0, payload)


def _error_access_denied(username: str) -> bytes:
    """ERR_1045: Access denied for user 'username'@'host' (using password: YES)."""
    msg = f"Access denied for user '{username}'@'honeypot' (using password: YES)"
    payload = (
        b"\xff"                          # ERR marker
        + struct.pack("<H", 1045)        # error code
        + b"#28000"                      # SQL state marker + state
        + msg.encode()
    )
    return _packet(2, payload)


def _read_packet(conn: socket.socket) -> bytes | None:
    """Read one MySQL packet from the socket."""
    header = b""
    while len(header) < 4:
        chunk = conn.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    length = struct.unpack("<I", header[:3] + b"\x00")[0]
    body = b""
    while len(body) < length:
        chunk = conn.recv(length - len(body))
        if not chunk:
            return None
        body += chunk
    return body


def _parse_handshake_response(data: bytes) -> dict:
    """
    Parse a HandshakeResponse41 packet.
    Returns dict with: capabilities, max_packet_size, charset, username,
    auth_response, auth_plugin, client_version (attributes if present).
    """
    result: dict = {}
    offset = 0

    if len(data) < 32:
        return result

    caps = struct.unpack_from("<I", data, offset)[0]
    result["capabilities"] = caps
    offset += 4

    result["max_packet_size"] = struct.unpack_from("<I", data, offset)[0]
    offset += 4

    result["charset"] = data[offset]
    offset += 1 + 23  # charset + 23 reserved bytes

    # username (null-terminated)
    end = data.index(b"\x00", offset)
    result["username"] = data[offset:end].decode(errors="replace")
    offset = end + 1

    # auth response (length-prefixed or null-terminated depending on caps)
    if caps & 0x00200000:  # CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
        auth_len = data[offset]
        offset += 1
        result["auth_response"] = data[offset:offset + auth_len].hex()
        offset += auth_len
    elif caps & 0x00008000:  # CLIENT_SECURE_CONNECTION
        auth_len = data[offset]
        offset += 1
        result["auth_response"] = data[offset:offset + auth_len].hex()
        offset += auth_len
    else:
        end = data.index(b"\x00", offset)
        result["auth_response"] = data[offset:end].hex()
        offset = end + 1

    # database (optional)
    if caps & 0x00000008 and offset < len(data):
        end = data.find(b"\x00", offset)
        if end != -1:
            result["database"] = data[offset:end].decode(errors="replace")
            offset = end + 1

    # auth plugin name (optional)
    if caps & 0x00080000 and offset < len(data):
        end = data.find(b"\x00", offset)
        if end != -1:
            result["auth_plugin"] = data[offset:end].decode(errors="replace")
            offset = end + 1

    # client attributes (optional)
    if caps & 0x00100000 and offset < len(data):
        try:
            attr_len = data[offset]
            offset += 1
            attrs: dict = {}
            end_attrs = offset + attr_len
            while offset < end_attrs:
                k_len = data[offset]; offset += 1
                k = data[offset:offset + k_len].decode(errors="replace"); offset += k_len
                v_len = data[offset]; offset += 1
                v = data[offset:offset + v_len].decode(errors="replace"); offset += v_len
                attrs[k] = v
            result["client_attributes"] = attrs
            if "_client_version" in attrs:
                result["client_version"] = attrs["_client_version"]
            if "_client_name" in attrs:
                result["client_name"] = attrs["_client_name"]
        except Exception:
            pass

    return result


def _handle_client(conn: socket.socket, addr: tuple) -> None:
    ip, port = addr[0], addr[1]
    session_id = uuid.uuid4().hex[:12]

    try:
        conn.settimeout(15)

        # Send server greeting
        conn.sendall(_handshake_v10())

        # Read client handshake response
        data = _read_packet(conn)
        if not data:
            return

        parsed = _parse_handshake_response(data)
        username = parsed.get("username", "unknown")

        geo = resolve(ip)
        ev = {
            "source_ip":    ip,
            "source_port":  port,
            "geo":          geo,
            "username":     username,
            "auth_plugin":  parsed.get("auth_plugin", "unknown"),
            "capabilities": parsed.get("capabilities"),
            "client_version": parsed.get("client_version", parsed.get("client_name", "unknown")),
            "session_id":   session_id,
        }
        if "client_attributes" in parsed:
            ev["client_attributes"] = parsed["client_attributes"]

        log_event("mysql", ev)
        notify("mysql", ev)
        print(f"[mysql] {ip} → user={username!r} plugin={parsed.get('auth_plugin','?')!r} [{geo.get('country','??')}]")

        # Send ERR_ACCESS_DENIED
        conn.sendall(_error_access_denied(username))

    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    except Exception as exc:
        print(f"[mysql] Error from {ip}: {exc}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description="MySQL Honeypot")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=3306)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.host, args.port))
    sock.listen(128)
    print(f"[mysql] Listening on {args.host}:{args.port}")

    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=_handle_client, args=(conn, addr), daemon=True).start()
        except KeyboardInterrupt:
            print("\n[mysql] Shutting down.")
            break
        except Exception as exc:
            print(f"[mysql] Accept error: {exc}")


if __name__ == "__main__":
    main()
