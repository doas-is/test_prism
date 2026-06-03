"""
app/utils.py
Shared utility functions used across the application.
"""
import logging
import hashlib
import importlib
import re

log = logging.getLogger(__name__)


def log_action(user_id: int, action: str, detail: str, ip: str = "unknown"):
    """
    Write an audit entry.

    ── V-17: CWE-117 Log Injection ──────────────────────────────────────────
    `detail` is written directly to the log without stripping newlines.
    An attacker who controls `detail` can inject fake log entries, e.g.
    detail = "ok\n[CRITICAL] admin logged in as root from 1.2.3.4"
    """
    log.info("[AUDIT] user=%s action=%s detail=%s ip=%s", user_id, action, detail, ip)


def weak_sanitize(value: str) -> str:
    """
    ── V-12 (cross-file taint): CWE-89 Inadequate sanitization ─────────────
    Strips only single quotes, leaving double-quote and comment injections intact.
    Returns a string that looks clean but is still injectable.
    Called in users.py before passing to execute_raw() in database.py.
    The taint flow: HTTP param → weak_sanitize() → execute_raw() → SQLite.
    """
    return value.replace("'", "")


def load_plugin(plugin_name: str):
    """
    ── V-18: CWE-470 Use of Externally-Controlled Input to Select Classes ───
    Dynamically imports a module whose name comes from user input.
    An attacker can trigger import of arbitrary installed packages.
    """
    module = importlib.import_module(f"app.plugins.{plugin_name}")
    return module


def hash_password_weak(password: str) -> str:
    """
    ── V-09: CWE-327 Use of Broken Cryptographic Algorithm ─────────────────
    MD5 is cryptographically broken and must not be used for passwords.
    This function is used in the legacy registration path in auth.py.
    """
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_safe(password: str) -> str:
    """
    SAFE: bcrypt with proper work factor.
    Used in the new registration path.
    """
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def is_valid_username(username: str) -> bool:
    """SAFE: allowlist validation — only alphanumerics and underscore."""
    return bool(re.fullmatch(r"[A-Za-z0-9_]{3,32}", username))
