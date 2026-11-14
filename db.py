"""SQLite storage: the append-only logs (audit, auto_log, postbacks) and the per-scope daily state.

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
    # one row per scope ("hook:<id>" or "manual"): today's counters and armed TP/SL. A write is one atomic statement.
    "CREATE TABLE IF NOT EXISTS state (scope TEXT PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    # failed-login counters ("ip:<addr>" and "*" for all addresses together); kept here so a restart doesn't unlock
    "CREATE TABLE IF NOT EXISTS lockouts (key TEXT PRIMARY KEY, count INTEGER NOT NULL, until REAL NOT NULL, last REAL NOT NULL)",
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


def reset():
    """Erase every stored record (logs, postbacks, daily state); the schema stays."""
    c = conn()
    for t in ("audit", "auto_log", "postbacks", "state", "lockouts"):
        c.execute(f"DELETE FROM {t}")
    c.execute("VACUUM")  # DELETE only marks pages free; rewrite the file so old rows aren't left on disk
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # and empty the write-ahead log, which holds recent rows


def export_all():
    """Every stored record as plain lists (the `data` JSON parsed), for the account export."""
    c = conn()
    j = json.loads
    return {
        "audit": [[r[0], r[1], j(r[2])] for r in c.execute("SELECT ts, event, data FROM audit ORDER BY id")],
        "auto_log": [[r[0], r[1], j(r[2])] for r in c.execute("SELECT ts, day, data FROM auto_log ORDER BY id")],
        "postbacks": [[r[0], r[1], r[2], r[3], j(r[4])]
                      for r in c.execute("SELECT ts, broker, order_id, status, data FROM postbacks ORDER BY id")],
        "state": [[r[0], r[1], j(r[2])] for r in c.execute("SELECT scope, ts, data FROM state")],
    }


def check_export(t):
    """Raise ValueError unless `t` has the shape export_all() produces."""
    shapes = {"audit": (3, (int, float), str, dict), "auto_log": (3, (int, float), str, dict),
              "postbacks": (5, (int, float), (str, type(None)), (str, type(None)), (str, type(None)), dict),
              "state": (3, str, (int, float), dict)}
    if not isinstance(t, dict) or set(t) != set(shapes):
        raise ValueError("database section is malformed")
    for name, rows in t.items():
        n = shapes[name][0]
        if not isinstance(rows, list):
            raise ValueError(f"{name} must be a list")
        for r in rows:
            if not (isinstance(r, list) and len(r) == n):
                raise ValueError(f"bad row in {name}")
            for v, ty in zip(r, shapes[name][1:]):
                if isinstance(v, bool) or not isinstance(v, ty):
                    raise ValueError(f"bad value in {name}")


def import_all(t):
    """Replace every stored record with the exported ones, all or nothing."""
    check_export(t)
    c = conn()
    dump = json.dumps
    c.execute("BEGIN")
    try:
        for tbl in ("audit", "auto_log", "postbacks", "state"):
            c.execute(f"DELETE FROM {tbl}")
        c.executemany("INSERT INTO audit(ts, event, data) VALUES (?,?,?)", [(a, b, dump(x)) for a, b, x in t["audit"]])
        c.executemany("INSERT INTO auto_log(ts, day, data) VALUES (?,?,?)", [(a, b, dump(x)) for a, b, x in t["auto_log"]])
        c.executemany("INSERT INTO postbacks(ts, broker, order_id, status, data) VALUES (?,?,?,?,?)",
                      [(a, b, o, s, dump(x)) for a, b, o, s, x in t["postbacks"]])
        c.executemany("INSERT OR REPLACE INTO state(scope, ts, data) VALUES (?,?,?)",
                      [(a, b, dump(x)) for a, b, x in t["state"]])
        c.execute("COMMIT")
    except Exception:
        c.execute("ROLLBACK")
        raise


def lock_get(key):
    """(count, locked_until, last_failure) for a login-lockout key; zeros if none."""
    r = conn().execute("SELECT count, until, last FROM lockouts WHERE key=?", (key,)).fetchone()
    return tuple(r) if r else (0, 0.0, 0.0)


def lock_set(key, count, until, last):
    conn().execute("INSERT OR REPLACE INTO lockouts(key, count, until, last) VALUES (?,?,?,?)", (key, count, until, last))


def lock_clear(*keys):
    for k in keys:
        conn().execute("DELETE FROM lockouts WHERE key=?", (k,))


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


def set_state(scope, st):
    conn().execute("INSERT OR REPLACE INTO state(scope, ts, data) VALUES (?,?,?)", (scope, time.time(), json.dumps(st)))


# ---------- reads ----------
def get_state(scope):
    r = conn().execute("SELECT data FROM state WHERE scope=?", (scope,)).fetchone()
    return json.loads(r[0]) if r else None



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


def latest_alert():
    """(id, ts) of the newest webhook alert in the automation log, or None. Cheap enough to poll."""
    r = conn().execute("SELECT id, ts FROM auto_log WHERE json_extract(data, '$.event') = 'alert' "
                       "ORDER BY id DESC LIMIT 1").fetchone()
    return (r[0], r[1]) if r else None


def latest_postback(broker, order_id):
    """Newest pushed update for an order with a status, or None."""
    r = conn().execute("SELECT data FROM postbacks WHERE broker=? AND order_id=? AND status IS NOT NULL "
                       "ORDER BY id DESC LIMIT 1", (broker, str(order_id))).fetchone()
    return json.loads(r[0]) if r else None
