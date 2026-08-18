import sqlite3
import os
import threading
from flask import g, current_app

_local = threading.local()


def get_db_path(app=None):
    app = app or current_app
    return app.config["DATABASE_PATH"]


def get_db():
    """Per-request (Flask g) connection for web requests."""
    if "db" not in g:
        g.db = sqlite3.connect(get_db_path(), detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


def get_db_nocontext(path):
    """Connection for use outside Flask's app/request context (DNS server
    thread). Keyed by path, not just by thread -- a thread that touches
    more than one database file (the test suite does this deliberately;
    a real running server never does) must get the right connection for
    the path it actually asked for, not whichever one it opened first."""
    if not hasattr(_local, "conns"):
        _local.conns = {}
    conn = _local.conns.get(path)
    if conn is None:
        conn = sqlite3.connect(path, check_same_thread=False, detect_types=sqlite3.PARSE_DECLTYPES, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
        _local.conns[path] = conn
    return conn


def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    path = get_db_path(app)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    first_time = not os.path.exists(path)
    conn = sqlite3.connect(path)
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, "r") as f:
        conn.executescript(f.read())
    _migrate(conn)
    conn.commit()
    conn.close()
    app.teardown_appcontext(close_db)
    return first_time


def _migrate(conn):
    """Additive, idempotent migrations for databases created by earlier
    versions. CREATE TABLE IF NOT EXISTS in schema.sql handles new
    tables automatically; this only needs to handle new COLUMNS on
    tables that already existed in prior versions."""
    cols = [r[1] for r in conn.execute("PRAGMA table_info(records)")]
    if "client_match" not in cols:
        conn.execute("ALTER TABLE records ADD COLUMN client_match TEXT")
    zone_cols = [r[1] for r in conn.execute("PRAGMA table_info(zones)")]
    if "nsec3_enabled" not in zone_cols:
        conn.execute("ALTER TABLE zones ADD COLUMN nsec3_enabled INTEGER NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE zones ADD COLUMN nsec3_salt TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE zones ADD COLUMN nsec3_iterations INTEGER NOT NULL DEFAULT 0")


def query(db, sql, args=(), one=False):
    cur = db.execute(sql, args)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(db, sql, args=()):
    cur = db.execute(sql, args)
    db.commit()
    return cur.lastrowid
