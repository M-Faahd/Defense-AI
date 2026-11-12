import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from app.core.config import DB_PATH

TOP_COLUMNS = {"source_ip", "username", "command", "event_type"}


def now_iso():
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def connect():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def initialize_database():
    with connect() as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                session_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                command TEXT,
                details TEXT,
                timestamp TEXT NOT NULL,
                received_at TEXT
            )
        """)
        cols = {r["name"] for r in db.execute(
            "PRAGMA table_info(security_events)")}
        if "received_at" not in cols:          # upgrade an older database
            db.execute(
                "ALTER TABLE security_events ADD COLUMN received_at TEXT")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_session "
                   "ON security_events(session_id)")
        db.execute("CREATE INDEX IF NOT EXISTS idx_events_ip "
                   "ON security_events(source_ip)")
        db.execute("""
            CREATE TABLE IF NOT EXISTS adaptations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                session_id TEXT,
                rule TEXT NOT NULL,
                action TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS analyses (
                session_id TEXT PRIMARY KEY,
                event_count INTEGER NOT NULL,
                result TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)


# ---------- events ----------

def save_event(event):
    event["received_at"] = now_iso()
    with connect() as db:
        cur = db.execute("""
            INSERT INTO security_events
            (source_ip, session_id, event_type, username, command,
             details, timestamp, received_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event["source_ip"], event["session_id"], event["event_type"],
            event.get("username"), event.get("command"),
            event.get("details"), event["timestamp"], event["received_at"],
        ))
        event["id"] = cur.lastrowid
    return event


def get_events(limit=200, session_id=None, event_type=None):
    query, args = "SELECT * FROM security_events WHERE 1=1", []
    if session_id:
        query += " AND session_id = ?"
        args.append(session_id)
    if event_type:
        query += " AND event_type = ?"
        args.append(event_type)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as db:
        return [dict(r) for r in db.execute(query, args)]


def get_events_for_session(session_id):
    with connect() as db:
        rows = db.execute("SELECT * FROM security_events "
                          "WHERE session_id = ? ORDER BY id ASC",
                          (session_id,))
        return [dict(r) for r in rows]


def get_events_for_ip(ip):
    with connect() as db:
        rows = db.execute("SELECT * FROM security_events "
                          "WHERE source_ip = ? ORDER BY id ASC", (ip,))
        return [dict(r) for r in rows]


def get_event_count():
    with connect() as db:
        return db.execute(
            "SELECT COUNT(*) AS n FROM security_events").fetchone()["n"]


def get_timeline(minutes=30):
    with connect() as db:
        rows = db.execute("""
            SELECT substr(timestamp, 1, 16) AS minute, COUNT(*) AS events
            FROM security_events GROUP BY minute
            ORDER BY minute DESC LIMIT ?
        """, (minutes,)).fetchall()
    return [dict(r) for r in reversed(rows)]


def get_top(column, limit=6):
    if column not in TOP_COLUMNS:
        raise ValueError("column not allowed")
    with connect() as db:
        rows = db.execute(f"""
            SELECT {column} AS value, COUNT(*) AS count
            FROM security_events
            WHERE {column} IS NOT NULL AND {column} != ''
            GROUP BY {column} ORDER BY count DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(r) for r in rows]


# ---------- adaptations ----------

def _adaptation(row):
    item = dict(row)
    item["detail"] = json.loads(item["detail"] or "{}")
    return item


def save_adaptation(ip, session_id, rule, action, detail):
    ts = now_iso()
    with connect() as db:
        cur = db.execute("""
            INSERT INTO adaptations
            (source_ip, session_id, rule, action, detail, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (ip, session_id, rule, action, json.dumps(detail), ts))
        row = db.execute("SELECT * FROM adaptations WHERE id = ?",
                         (cur.lastrowid,)).fetchone()
    return _adaptation(row)


def adaptation_exists(ip, rule):
    with connect() as db:
        return db.execute("SELECT 1 FROM adaptations "
                          "WHERE source_ip = ? AND rule = ?",
                          (ip, rule)).fetchone() is not None


def get_adaptations(limit=100):
    with connect() as db:
        rows = db.execute("SELECT * FROM adaptations "
                          "ORDER BY id DESC LIMIT ?", (limit,))
        return [_adaptation(r) for r in rows]


def get_adaptations_for_ip(ip):
    with connect() as db:
        rows = db.execute("SELECT * FROM adaptations "
                          "WHERE source_ip = ? ORDER BY id ASC", (ip,))
        return [_adaptation(r) for r in rows]


# ---------- cached AI analyses ----------

def save_analysis(session_id, event_count, result):
    with connect() as db:
        db.execute("""
            INSERT OR REPLACE INTO analyses
            (session_id, event_count, result, created_at)
            VALUES (?, ?, ?, ?)
        """, (session_id, event_count, json.dumps(result), now_iso()))


def get_analysis(session_id):
    with connect() as db:
        row = db.execute("SELECT * FROM analyses WHERE session_id = ?",
                         (session_id,)).fetchone()
    if not row:
        return None
    result = json.loads(row["result"])
    result["event_count"] = row["event_count"]
    result["analyzed_at"] = row["created_at"]
    return result


def reset_all():
    with connect() as db:
        for table in ("security_events", "adaptations", "analyses"):
            db.execute(f"DELETE FROM {table}")
