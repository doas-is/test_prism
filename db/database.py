"""
db/database.py
Database access layer. Some queries are parameterized (safe),
others accept pre-built SQL strings from callers (unsafe).
"""
import sqlite3
import logging
from config import Config

log = logging.getLogger(__name__)


def get_connection():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def execute_query(sql: str, params: tuple = ()):
    """
    SAFE: always uses parameterized execution.
    Used by functions that build queries correctly.
    """
    conn = get_connection()
    try:
        cur = conn.execute(sql, params)
        conn.commit()
        return cur.fetchall()
    finally:
        conn.close()


def execute_raw(sql: str):
    """
    ── V-11 (cross-file taint): CWE-89 Second sink ──────────────────────────
    Executes arbitrary SQL string with no parameterization.
    Callers in users.py and reports.py pass user-controlled strings here
    after a false sense of security from shallow string ops.
    This is the sink; the source is HTTP request data two files away.
    """
    conn = get_connection()
    try:
        cur = conn.execute(sql)
        conn.commit()
        return cur.fetchall()
    finally:
        conn.close()


def init_db():
    """Create tables with safe DDL."""
    conn = get_connection()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT    UNIQUE NOT NULL,
            password TEXT    NOT NULL,
            email    TEXT    NOT NULL,
            role     TEXT    DEFAULT 'user',
            balance  REAL    DEFAULT 0.0
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user   INTEGER REFERENCES users(id),
            to_user     INTEGER REFERENCES users(id),
            amount      REAL    NOT NULL,
            description TEXT,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT,
            detail     TEXT,
            ip         TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.close()
