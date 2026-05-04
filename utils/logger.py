"""
Shared structured logger — writes JSON lines to per-service .jsonl files
and inserts rows into a shared SQLite database for dashboard queries.
"""

import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(os.getenv("HONEYNET_LOG_DIR", "logs"))
DB_PATH = Path(os.getenv("HONEYNET_DB_PATH", "logs/honeynet.db"))

LOG_DIR.mkdir(parents=True, exist_ok=True)

_db_lock = threading.Lock()
_file_locks: dict[str, threading.Lock] = {}
_file_lock_meta = threading.Lock()


def _get_file_lock(path: str) -> threading.Lock:
    with _file_lock_meta:
        if path not in _file_locks:
            _file_locks[path] = threading.Lock()
        return _file_locks[path]


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT    NOT NULL,
            service     TEXT    NOT NULL,
            source_ip   TEXT    NOT NULL,
            source_port INTEGER,
            country     TEXT,
            city        TEXT,
            asn         TEXT,
            username    TEXT,
            password    TEXT,
            method      TEXT,
            path        TEXT,
            user_agent  TEXT,
            post_body   TEXT,
            client_ver  TEXT,
            auth_plugin TEXT,
            extra       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_service ON events(service);
        CREATE INDEX IF NOT EXISTS idx_events_ip      ON events(source_ip);
    """)
    conn.commit()


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    _init_db(conn)
    return conn


_db_conn: sqlite3.Connection | None = None
_db_conn_lock = threading.Lock()


def _db() -> sqlite3.Connection:
    global _db_conn
    with _db_conn_lock:
        if _db_conn is None:
            _db_conn = _get_db()
        return _db_conn


def log_event(service: str, event: dict) -> None:
    """
    Write one event to the per-service .jsonl file and to SQLite.
    `event` must contain at minimum: source_ip, timestamp (ISO-8601 UTC string).
    Any extra keys are stored in the `extra` JSON column.
    """
    if "timestamp" not in event:
        event["timestamp"] = datetime.now(timezone.utc).isoformat()

    event["service"] = service

    # ── JSONL file ────────────────────────────────────────────────────────────
    jsonl_path = str(LOG_DIR / f"{service}_events.jsonl")
    lock = _get_file_lock(jsonl_path)
    with lock:
        with open(jsonl_path, "a") as f:
            f.write(json.dumps(event, default=str) + "\n")

    # ── SQLite ────────────────────────────────────────────────────────────────
    geo = event.get("geo", {})
    known_cols = {
        "ts":          event.get("timestamp"),
        "service":     service,
        "source_ip":   event.get("source_ip", ""),
        "source_port": event.get("source_port"),
        "country":     geo.get("country"),
        "city":        geo.get("city"),
        "asn":         geo.get("asn"),
        "username":    event.get("username"),
        "password":    event.get("password"),
        "method":      event.get("method"),
        "path":        event.get("path"),
        "user_agent":  event.get("user_agent"),
        "post_body":   json.dumps(event.get("post_body")) if event.get("post_body") else None,
        "client_ver":  event.get("client_version"),
        "auth_plugin": event.get("auth_plugin"),
    }
    skip = set(known_cols.keys()) | {"timestamp", "service", "geo", "session_id"}
    extra = {k: v for k, v in event.items() if k not in skip}
    known_cols["extra"] = json.dumps(extra) if extra else None

    cols = list(known_cols.keys())
    placeholders = ", ".join("?" for _ in cols)
    values = [known_cols[c] for c in cols]
    sql = f"INSERT INTO events ({', '.join(cols)}) VALUES ({placeholders})"

    with _db_lock:
        try:
            _db().execute(sql, values)
            _db().commit()
        except Exception as exc:
            print(f"[logger] DB write error: {exc}")


def query_events(
    service: str | None = None,
    limit: int = 200,
    offset: int = 0,
    since_ts: str | None = None,
) -> list[dict]:
    """Return events from SQLite as a list of dicts, newest first."""
    clauses = []
    params: list = []
    if service:
        clauses.append("service = ?")
        params.append(service)
    if since_ts:
        clauses.append("ts >= ?")
        params.append(since_ts)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT * FROM events
        {where}
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]
    with _db_lock:
        rows = _db().execute(sql, params).fetchall()
    return [dict(r) for r in rows]


def count_events(service: str | None = None, since_ts: str | None = None) -> int:
    clauses = []
    params: list = []
    if service:
        clauses.append("service = ?")
        params.append(service)
    if since_ts:
        clauses.append("ts >= ?")
        params.append(since_ts)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"SELECT COUNT(*) FROM events {where}"
    with _db_lock:
        return _db().execute(sql, params).fetchone()[0]
