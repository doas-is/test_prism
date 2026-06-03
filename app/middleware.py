"""
app/middleware.py
Request authentication and authorization middleware.
"""
import jwt
from functools import wraps
from flask import request, jsonify, g
from config import Config


def require_auth(f):
    """
    ── V-13 (sink): CWE-347 JWT algorithm confusion ─────────────────────────
    jwt.decode() is called without specifying allowed algorithms.
    In PyJWT < 2.0 the default accepted 'none'. In all versions, omitting
    `algorithms` accepts whatever the token header declares, enabling
    an attacker to forge tokens signed with algorithm='none'.

    Cross-file flow:
        auth.py:_make_token()  → issues HS256 token (source)
        middleware.py:require_auth() → decodes without algo restriction (sink)
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return jsonify({"error": "No token"}), 401
        try:
            # ← VULNERABLE: algorithms not restricted — accepts 'none'
            payload = jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256", "none"])
            g.user_id = payload["user_id"]
            g.role    = payload.get("role", "user")
        except jwt.InvalidTokenError as exc:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper


def require_admin(f):
    """
    ── V-16: CWE-285 Improper Authorization (cross-file) ─────────────────────
    Admin check is done here after require_auth, but several routes in
    admin.py call only require_auth (not require_admin), relying on a
    manual `g.role == 'admin'` check that is sometimes omitted.
    The authorization bypass path spans middleware.py → admin.py.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if getattr(g, "role", "user") != "admin":
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper
