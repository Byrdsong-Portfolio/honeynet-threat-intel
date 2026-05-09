"""
Alerting — sends a Discord webhook message when a new attacker hits any service.
Set DISCORD_WEBHOOK_URL in .env or your environment to enable.
Alerts are rate-limited to one per IP per service per cooldown window.
"""

import os
import threading
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv

# Load .env before reading any env vars so this works both under systemd
# (EnvironmentFile already set them; load_dotenv is a no-op) and when
# running scripts directly for testing (dotenv populates them now).
load_dotenv()

COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "3600"))

_COLORS = {
    "ssh":   0xE74C3C,
    "http":  0xF39C12,
    "mysql": 0x3498DB,
}

_last_alert: dict[tuple[str, str], float] = {}
_alert_lock = threading.Lock()

# HTTP paths worth alerting on — everything else is too noisy
_SENSITIVE_PATHS = {
    "/", "/admin", "/admin/", "/admin/login",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/phpMyAdmin",
    "/wp-login.php", "/wp-admin",
    "/.env", "/.env.backup", "/.env.local",
    "/backup/credentials.txt", "/admin/credentials.txt", "/config/credentials.txt",
    "/backup/dump.sql", "/admin/dump.sql",
    "/backup/employees.csv", "/admin/employees.csv",
    "/.git/config", "/config.php", "/wp-config.php",
}


def _webhook_url() -> str:
    # Re-read at call time so a late-set env var is picked up without restart.
    return os.getenv("DISCORD_WEBHOOK_URL", "")


def validate_webhook() -> bool:
    """
    Call once at startup. GETs the webhook to verify it's reachable and valid.
    Returns True if ok, False otherwise (also prints a clear status line).
    """
    url = _webhook_url()
    if not url:
        print("[alerting] DISCORD_WEBHOOK_URL not set — Discord alerts disabled.")
        return False
    if not url.startswith("https://discord.com/api/webhooks/"):
        print(f"[alerting] DISCORD_WEBHOOK_URL looks malformed: {url[:80]!r}")
        print("[alerting]   Expected: https://discord.com/api/webhooks/<id>/<token>")
        return False
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            print("[alerting] Discord webhook validated OK.")
            return True
        print(f"[alerting] Webhook GET returned HTTP {resp.status_code} — URL may be wrong or revoked.")
        return False
    except requests.RequestException as exc:
        print(f"[alerting] Webhook validation failed (network error): {exc}")
        return False


def _should_alert(service: str, ip: str) -> bool:
    key = (service, ip)
    now = time.time()
    with _alert_lock:
        if now - _last_alert.get(key, 0) < COOLDOWN_SECONDS:
            return False
        _last_alert[key] = now
    return True


def _send_webhook(payload: dict, retries: int = 3) -> bool:
    url = _webhook_url()
    if not url:
        return False
    for attempt in range(retries):
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 204:
                return True
            if resp.status_code == 429:
                retry_after = float(resp.headers.get("Retry-After", "5"))
                print(f"[alerting] Discord rate limited — waiting {retry_after}s before retry")
                time.sleep(retry_after)
                continue
            print(f"[alerting] Webhook returned HTTP {resp.status_code}: {resp.text[:200]}")
            return False
        except requests.RequestException as exc:
            wait = 2 ** attempt
            print(f"[alerting] Webhook error (attempt {attempt + 1}/{retries}): {exc}")
            if attempt < retries - 1:
                time.sleep(wait)
    return False


def notify(service: str, event: dict) -> None:
    """
    Fire a Discord embed for a new attacker event. Non-blocking — daemon thread.
    For HTTP, only fires on POST requests or hits to sensitive paths to avoid
    burning the per-IP cooldown on trivial scanner noise.
    """
    if not _webhook_url():
        return

    if service == "http":
        method = event.get("method", "GET")
        path   = event.get("path", "/")
        if method != "POST" and path not in _SENSITIVE_PATHS:
            return

    ip = event.get("source_ip", "unknown")
    if not _should_alert(service, ip):
        return

    threading.Thread(target=_dispatch, args=(service, event), daemon=True).start()


def _dispatch(service: str, event: dict) -> None:
    geo     = event.get("geo", {})
    country = geo.get("country", "??")
    city    = geo.get("city", "Unknown")
    asn     = geo.get("asn", "Unknown")
    ip      = event.get("source_ip", "unknown")
    ts      = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    detail_lines: list[str] = []
    if service == "ssh":
        detail_lines = [
            f"**Username:** `{event.get('username', '-')}`",
            f"**Password:** `{event.get('password', '-')}`",
            f"**Client:** `{event.get('client_version', '-')}`",
        ]
    elif service == "http":
        method = event.get("method", "-")
        path   = event.get("path", "-")
        ua     = event.get("user_agent", "-")
        detail_lines = [
            f"**Method:** `{method} {path}`",
            f"**User-Agent:** `{ua[:80]}`",
        ]
        pb = event.get("post_body")
        if pb:
            detail_lines.append(f"**POST body:** `{str(pb)[:120]}`")
    elif service == "mysql":
        detail_lines = [
            f"**Username:** `{event.get('username', '-')}`",
            f"**Auth plugin:** `{event.get('auth_plugin', '-')}`",
        ]

    description = "\n".join([
        f"**IP:** `{ip}`",
        f"**Location:** {country} / {city} ({asn})",
        f"**Time:** {ts}",
        "",
    ] + detail_lines)

    payload = {
        "embeds": [{
            "title":       f":warning: New {service.upper()} hit",
            "description": description,
            "color":       _COLORS.get(service, 0x95A5A6),
            "footer":      {"text": "Honeynet Suite"},
        }]
    }
    _send_webhook(payload)
