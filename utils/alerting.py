"""
Alerting — sends a Discord webhook message when a new attacker hits any service.
Set DISCORD_WEBHOOK_URL in your environment or .env file to enable.
Alerts are rate-limited to one per IP per service per hour to avoid spam.
"""

import json
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

# (service, ip) -> last alert epoch
_last_alert: dict[tuple[str, str], float] = {}
_alert_lock = threading.Lock()
COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "3600"))

# Service color bars for Discord embeds
_COLORS = {
    "ssh":   0xE74C3C,   # red
    "http":  0xF39C12,   # amber
    "mysql": 0x3498DB,   # blue
}


def _should_alert(service: str, ip: str) -> bool:
    key = (service, ip)
    now = time.time()
    with _alert_lock:
        last = _last_alert.get(key, 0)
        if now - last < COOLDOWN_SECONDS:
            return False
        _last_alert[key] = now
    return True


def _send_webhook(payload: dict) -> None:
    if not DISCORD_WEBHOOK_URL:
        return
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            pass  # 204 No Content on success
    except Exception as exc:
        print(f"[alerting] Webhook error: {exc}")


def notify(service: str, event: dict) -> None:
    """
    Fire a Discord embed for a new attacker event.
    Call this from each honeypot after logging.
    Non-blocking — runs in a daemon thread.
    """
    if not DISCORD_WEBHOOK_URL:
        return

    ip = event.get("source_ip", "unknown")
    if not _should_alert(service, ip):
        return

    threading.Thread(target=_dispatch, args=(service, event), daemon=True).start()


def _dispatch(service: str, event: dict) -> None:
    geo = event.get("geo", {})
    country = geo.get("country", "??")
    city    = geo.get("city", "Unknown")
    asn     = geo.get("asn", "Unknown")
    ip      = event.get("source_ip", "unknown")
    ts      = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    # Build service-specific detail line
    detail_lines: list[str] = []
    if service == "ssh":
        u = event.get("username", "-")
        p = event.get("password", "-")
        cv = event.get("client_version", "-")
        detail_lines = [
            f"**Username:** `{u}`",
            f"**Password:** `{p}`",
            f"**Client:** `{cv}`",
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
        u  = event.get("username", "-")
        ap = event.get("auth_plugin", "-")
        detail_lines = [
            f"**Username:** `{u}`",
            f"**Auth plugin:** `{ap}`",
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
