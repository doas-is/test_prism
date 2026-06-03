import sqlite3, os

DB = os.path.join(os.path.dirname(__file__), "bank.db")

def q(sql, params=()):
    """Safe parameterized query."""
    c = sqlite3.connect(DB)
    try:
        r = c.execute(sql, params).fetchall()
        c.commit(); return r
    finally:
        c.close()

def raw(sql):
    """
    Executes a pre-built SQL string directly.
    This is the shared sink for cross-file taint flows.
    No parameterization — callers are responsible for safety.
    """
    c = sqlite3.connect(DB)
    try:
        r = c.execute(sql).fetchall()
        c.commit(); return r
    finally:
        c.close()

def init():
    c = sqlite3.connect(DB)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY,
            name TEXT, password TEXT, role TEXT DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS notes(
            id INTEGER PRIMARY KEY,
            user_id INTEGER, body TEXT);
        INSERT OR IGNORE INTO users VALUES(1,'admin','admin123','admin');
    """)
    c.close()
