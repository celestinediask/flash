"""SQLite storage for the append-only logs: audit, auto_log and postbacks.

One file (flash.db, or $DB_PATH) shared by ui_server.py and postback_server.py. WAL mode lets the two processes
read and write at the same time. Every record is stored whole as JSON in `data`, so the dicts that come back are
exactly the dicts the old .jsonl files held; the other columns are only there to index and filter.
Each thread gets its own connection (sqlite3 connections must not be shared across threads).
"""
import datetime
import json
import os
import sqlite3
import threading
import time
import zoneinfo

HERE = os.path.dirname(os.path.abspath(__file__))
IST = zoneinfo.ZoneInfo("Asia/Kolkata")
_local = threading.local()

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY, ts REAL NOT NULL, event TEXT NOT NULL, data TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS audit_event ON audit(event, id)",
    """CREATE TABLE IF NOT EXISTS auto_log (
        id INTEGER PRIMARY KEY, ts REAL NOT NULL, day TEXT NOT NULL, data TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS auto_log_day ON auto_log(day, ts)",
    """CREATE TABLE IF NOT EXISTS postbacks (
        id INTEGER PRIMARY KEY, ts REAL NOT NULL, broker TEXT, order_id TEXT, status TEXT, data TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS postbacks_order ON postbacks(broker, order_id, id)",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
]
SCHEMA_VERSION = "1"


def db_path():
    return os.environ.get("DB_PATH") or os.path.join(HERE, "flash.db")


def conn():
    """This thread's connection, opened (and the schema created) on first use."""
    path = db_path()
    c = getattr(_local, "conn", None)
    if c is not None and getattr(_local, "path", None) == path:
        return c
    c = sqlite3.connect(path, timeout=10, isolation_level=None)  # autocommit; use BEGIN explicitly if needed
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA busy_timeout=5000")
    c.execute("PRAGMA synchronous=NORMAL")  # safe with WAL: a crash can lose the last commit, never corrupt the file
    for stmt in SCHEMA:
        c.execute(stmt)
    c.execute("INSERT OR IGNORE INTO meta VALUES ('schema_version', ?)", (SCHEMA_VERSION,))
    try:
        os.chmod(path, 0o600)  # holds order history; keep it private like the other data files
    except OSError:
        pass
    _local.conn, _local.path = c, path
    return c


def day_of(ts):
    return datetime.datetime.fromtimestamp(ts or 0, IST).strftime("%Y-%m-%d")


# ---------- writes ----------
def add_audit(event, **kw):
    rec = {"ts": time.time(), "event": event, **kw}
    conn().execute("INSERT INTO audit(ts, event, data) VALUES (?,?,?)", (rec["ts"], event, json.dumps(rec)))


def add_auto_log(**kw):
    rec = {"ts": time.time(), **kw}
    conn().execute("INSERT INTO auto_log(ts, day, data) VALUES (?,?,?)", (rec["ts"], day_of(rec["ts"]), json.dumps(rec)))


def add_postback(rec):
    """rec: the dict postback_server builds ({"received", "broker", order_id, status, ..., "raw"})."""
    conn().execute("INSERT INTO postbacks(ts, broker, order_id, status, data) VALUES (?,?,?,?,?)",
                   (rec.get("received") or time.time(), rec.get("broker"),
                    str(rec["order_id"]) if rec.get("order_id") else None, rec.get("status"), json.dumps(rec)))


# ---------- reads ----------
def audit_events(*events):
    """Audit records (oldest first), optionally only the named event types."""
    sql, args = "SELECT data FROM audit", ()
    if events:
        sql += " WHERE event IN (%s)" % ",".join("?" * len(events))
        args = events
    return [json.loads(r[0]) for r in conn().execute(sql + " ORDER BY id", args)]


def auto_log_entries(day=None):
    """Automation log records (oldest first), optionally for one IST day (YYYY-MM-DD)."""
    if day:
        rows = conn().execute("SELECT data FROM auto_log WHERE day=? ORDER BY id", (day,))
    else:
        rows = conn().execute("SELECT data FROM auto_log ORDER BY id")
    return [json.loads(r[0]) for r in rows]


def auto_log_days():
    return {r[0] for r in conn().execute("SELECT DISTINCT day FROM auto_log")}


def latest_postback(broker, order_id):
    """Newest pushed update for an order with a status, or None."""
    r = conn().execute("SELECT data FROM postbacks WHERE broker=? AND order_id=? AND status IS NOT NULL "
                       "ORDER BY id DESC LIMIT 1", (broker, str(order_id))).fetchone()
    return json.loads(r[0]) if r else None


# ---------- one-time import of the old .jsonl files ----------
def import_jsonl(path, kind):
    """Load an old log file into its table. kind: 'audit' | 'auto_log' | 'postbacks'.
    Idempotent: a file is imported once (recorded in meta); the file itself is left untouched.
    Returns (imported, skipped_bad_lines), or None if it was already imported or is missing."""
    key = f"imported:{kind}:{os.path.basename(path)}"
    c = conn()
    if not os.path.exists(path) or c.execute("SELECT 1 FROM meta WHERE key=?", (key,)).fetchone():
        return None
    n = bad = 0
    c.execute("BEGIN IMMEDIATE")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                    if not isinstance(e, dict):
                        raise ValueError
                except ValueError:
                    bad += 1
                    continue
                if kind == "audit":
                    c.execute("INSERT INTO audit(ts, event, data) VALUES (?,?,?)",
                              (e.get("ts", 0), e.get("event", ""), json.dumps(e)))
                elif kind == "auto_log":
                    c.execute("INSERT INTO auto_log(ts, day, data) VALUES (?,?,?)",
                              (e.get("ts", 0), day_of(e.get("ts", 0)), json.dumps(e)))
                else:
                    c.execute("INSERT INTO postbacks(ts, broker, order_id, status, data) VALUES (?,?,?,?,?)",
                              (e.get("received", 0), e.get("broker"),
                               str(e["order_id"]) if e.get("order_id") else None, e.get("status"), json.dumps(e)))
                n += 1
        c.execute("INSERT INTO meta VALUES (?,?)", (key, str(n)))
        c.execute("COMMIT")
    except BaseException:
        c.execute("ROLLBACK")
        raise
    return n, bad
