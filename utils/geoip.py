"""
IP geolocation helper.
Tries GeoIP2 (MaxMind DB) first, falls back to ip-api.com REST if no DB is
present. Results are cached in memory for the process lifetime.
"""

import functools
import os
import socket
from pathlib import Path

# Optional: set GEOIP_DB_PATH to a MaxMind GeoLite2-City.mmdb file.
GEOIP_DB_PATH = os.getenv("GEOIP_DB_PATH", "")

_reader = None
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
    "172.29.", "172.30.", "172.31.", "192.168.", "127.", "::1", "fc", "fd",
)


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


def _load_reader():
    global _reader
    if _reader is not None:
        return _reader
    if GEOIP_DB_PATH and Path(GEOIP_DB_PATH).exists():
        try:
            import geoip2.database
            _reader = geoip2.database.Reader(GEOIP_DB_PATH)
        except Exception:
            _reader = None
    return _reader


@functools.lru_cache(maxsize=4096)
def _lookup_api(ip: str) -> dict:
    """Fallback: ip-api.com free tier (no key, 45 req/min)."""
    try:
        import urllib.request
        import json
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,org"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read())
        if data.get("status") == "success":
            return {
                "country": data.get("countryCode", "??"),
                "city":    data.get("city", "Unknown"),
                "asn":     data.get("org", "Unknown"),
            }
    except Exception:
        pass
    return {"country": "??", "city": "Unknown", "asn": "Unknown"}


def resolve(ip: str) -> dict:
    """
    Return {"country": str, "city": str, "asn": str} for an IP address.
    Returns placeholder dict for private/loopback addresses.
    """
    if _is_private(ip):
        return {"country": "private", "city": "local", "asn": "private"}

    reader = _load_reader()
    if reader:
        try:
            resp = reader.city(ip)
            return {
                "country": resp.country.iso_code or "??",
                "city":    resp.city.name or "Unknown",
                "asn":     f"AS{resp.traits.autonomous_system_number}" if hasattr(resp, "traits") else "Unknown",
            }
        except Exception:
            pass

    return _lookup_api(ip)
