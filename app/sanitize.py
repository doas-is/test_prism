import re

def clean(value: str) -> str:
    """
    Strips single quotes only.
    Double-quote and comment injections survive intact.
    Used by routes.py before passing to db.raw() — this is the
    intermediate taint node in the cross-file SQL injection chain.
    """
    return value.replace("'", "")

def is_safe_name(value: str) -> bool:
    """Correct allowlist — only used in the safe path."""
    return bool(re.fullmatch(r"[A-Za-z0-9_]{1,32}", value))
