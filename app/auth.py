"""
app/auth.py
Authentication routes: login, logout, register.
"""
import jwt
import datetime
from flask import Blueprint, request, jsonify, redirect
from db.database import get_connection, execute_query
from app.utils import hash_password_weak, hash_password_safe, log_action
from config import Config

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    ── V-01: CWE-89 SQL Injection ────────────────────────────────────────────
    Username and password are interpolated directly into the SQL string.
    Payload: username = ' OR '1'='1'--
    CodeQL taint path: request.json → username → sql string → conn.execute()
    """
    data     = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_connection()
    # ← VULNERABLE: f-string interpolation of user input into SQL
    sql  = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    row  = conn.execute(sql).fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "Invalid credentials"}), 401

    token = _make_token(row["id"], row["role"])
    log_action(row["id"], "login", f"success from {request.remote_addr}")
    return jsonify({"token": token, "user_id": row["id"]})


@auth_bp.route("/register", methods=["POST"])
def register():
    """
    Mixes safe validation with weak hashing.
    V-09 is triggered here: new users get MD5-hashed passwords.
    """
    data     = request.get_json(force=True)
    username = data.get("username", "")
    password = data.get("password", "")
    email    = data.get("email", "")

    if not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    # ← V-09: MD5 used instead of bcrypt
    hashed = hash_password_weak(password)

    try:
        execute_query(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            (username, hashed, email),
        )
    except Exception as exc:
        # ← V-20 (partial): exception detail exposed to caller — see also admin.py
        return jsonify({"error": str(exc)}), 400

    return jsonify({"status": "registered"})


@auth_bp.route("/logout")
def logout():
    """
    ── V-10: CWE-601 Open Redirect ──────────────────────────────────────────
    The `next` parameter is taken directly from the query string and used
    in a redirect without validation against an allowlist of trusted URLs.
    Payload: /auth/logout?next=https://evil.example.com/phish
    """
    next_url = request.args.get("next", "/")
    # ← VULNERABLE: redirect to arbitrary URL supplied by user
    return redirect(next_url)


def _make_token(user_id: int, role: str) -> str:
    """
    ── V-13: CWE-347 Improper Verification of Cryptographic Signature ────────
    Tokens are created with HS256 but the verify path in middleware.py
    accepts algorithm='none' due to a misconfigured decode call.
    This function is the source; the flaw is completed in middleware.py.
    """
    payload = {
        "user_id": user_id,
        "role":    role,
        "exp":     datetime.datetime.utcnow() + datetime.timedelta(hours=8),
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm="HS256")


def verify_token_safe(token: str) -> dict:
    """
    SAFE: enforces algorithm explicitly. Not used everywhere — see middleware.py.
    """
    return jwt.decode(token, Config.JWT_SECRET, algorithms=["HS256"])
