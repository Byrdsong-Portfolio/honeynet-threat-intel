#!/usr/bin/env python3
"""
Honeynet Dashboard — Flask app on port 5000.

Provides:
  - /           → visual overview (charts, top IPs, top credentials, path heatmap)
  - /api/events → JSON event feed for the live table (last N events)
  - /api/stats  → aggregate stats for chart rendering
  - /api/top    → top credentials, IPs, paths
  - SocketIO    → pushes new_event to connected browsers in real time

Keep this port firewall-restricted to your own IP. It is not a honeypot
surface — it's the management UI.

Run:
    python3 dashboard/app.py [--host 127.0.0.1] [--port 5000]
"""

import argparse
import json
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from flask_socketio import SocketIO

sys.path.insert(0, str(Path(__file__).parent.parent))
from utils.logger import query_events, count_events, _db, _db_lock

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = os.getenv("DASHBOARD_SECRET", "honeynet-dashboard-dev")
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ── Helpers ───────────────────────────────────────────────────────────────────

def _iso_ago(hours: int) -> str:
    dt = datetime.now(timezone.utc) - timedelta(hours=hours)
    return dt.isoformat()


def _top_n(sql: str, params: list, n: int = 20) -> list[dict]:
    with _db_lock:
        rows = _db().execute(sql, params).fetchmany(n)
    return [{"value": r[0], "count": r[1]} for r in rows]


# ── API routes ────────────────────────────────────────────────────────────────

@app.route("/api/events")
def api_events():
    service = request.args.get("service")
    limit   = min(int(request.args.get("limit", 100)), 500)
    offset  = int(request.args.get("offset", 0))
    since   = request.args.get("since")
    events  = query_events(service=service, limit=limit, offset=offset, since_ts=since)
    return jsonify(events)


@app.route("/api/stats")
def api_stats():
    """Hourly event counts per service for the past 24h, usable by Chart.js."""
    now = datetime.now(timezone.utc)
    hours = []
    for i in range(23, -1, -1):
        start = (now - timedelta(hours=i + 1)).isoformat()
        end   = (now - timedelta(hours=i)).isoformat()
        row: dict = {"hour": (now - timedelta(hours=i)).strftime("%H:00")}
        for svc in ("ssh", "http", "mysql"):
            with _db_lock:
                count = _db().execute(
                    "SELECT COUNT(*) FROM events WHERE service=? AND ts>=? AND ts<?",
                    [svc, start, end]
                ).fetchone()[0]
            row[svc] = count
        hours.append(row)
    return jsonify(hours)


@app.route("/api/top")
def api_top():
    window_h = int(request.args.get("hours", 168))  # default 7 days
    since    = _iso_ago(window_h)

    top_ips = _top_n(
        "SELECT source_ip, COUNT(*) c FROM events WHERE ts>=? GROUP BY source_ip ORDER BY c DESC",
        [since]
    )
    top_usernames = _top_n(
        "SELECT username, COUNT(*) c FROM events WHERE username IS NOT NULL AND ts>=? "
        "GROUP BY username ORDER BY c DESC",
        [since]
    )
    top_passwords = _top_n(
        "SELECT password, COUNT(*) c FROM events WHERE password IS NOT NULL AND ts>=? "
        "GROUP BY password ORDER BY c DESC",
        [since]
    )
    top_paths = _top_n(
        "SELECT path, COUNT(*) c FROM events WHERE path IS NOT NULL AND ts>=? "
        "GROUP BY path ORDER BY c DESC",
        [since]
    )
    top_countries = _top_n(
        "SELECT country, COUNT(*) c FROM events WHERE country IS NOT NULL AND ts>=? "
        "GROUP BY country ORDER BY c DESC",
        [since]
    )

    return jsonify({
        "top_ips":        top_ips,
        "top_usernames":  top_usernames,
        "top_passwords":  top_passwords,
        "top_paths":      top_paths,
        "top_countries":  top_countries,
    })


@app.route("/api/summary")
def api_summary():
    since_24h = _iso_ago(24)
    since_7d  = _iso_ago(168)
    return jsonify({
        "total_events":    count_events(),
        "events_24h":      count_events(since_ts=since_24h),
        "events_7d":       count_events(since_ts=since_7d),
        "ssh_24h":         count_events(service="ssh",   since_ts=since_24h),
        "http_24h":        count_events(service="http",  since_ts=since_24h),
        "mysql_24h":       count_events(service="mysql", since_ts=since_24h),
    })


# ── Main page ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── SocketIO: live event push ──────────────────────────────────────────────────

def _tail_events() -> None:
    """Background thread: poll for new events and push via SocketIO."""
    last_id = 0
    while True:
        try:
            with _db_lock:
                rows = _db().execute(
                    "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT 50",
                    [last_id]
                ).fetchall()
            for row in rows:
                ev = dict(row)
                last_id = ev["id"]
                socketio.emit("new_event", ev)
        except Exception:
            pass
        time.sleep(2)


@socketio.on("connect")
def on_connect():
    pass  # client connected — live updates will flow via _tail_events


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Honeynet Dashboard")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (keep to 127.0.0.1 or your own IP)")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    threading.Thread(target=_tail_events, daemon=True).start()
    print(f"[dashboard] Listening on http://{args.host}:{args.port}")
    socketio.run(app, host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
