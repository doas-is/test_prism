"""
app/admin.py
Administrative endpoints. Should be restricted to admin role only —
but some routes use only require_auth, relying on a manual role check
that is inconsistently applied (V-16).
"""
import os
import subprocess
import requests as http_requests
from flask import Blueprint, request, jsonify, g
from db.database import execute_query
from app.middleware import require_auth   # ← note: require_admin NOT imported here
from app.utils import log_action
from config import Config

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/ping", methods=["POST"])
@require_auth
def ping_host():
    """
    ── V-05: CWE-78 OS Command Injection ─────────────────────────────────────
    The `host` parameter is passed directly to subprocess without sanitization.
    Payload: {"host": "8.8.8.8; cat /etc/passwd"}
    CodeQL taint: request.json["host"] → subprocess.check_output(shell=True)

    ── V-16 (partial): CWE-285 Missing admin authorization check ─────────────
    This route uses @require_auth but not @require_admin. Any authenticated
    user can invoke OS commands. The admin check was intended but omitted.
    Cross-file: middleware.py defines require_admin; this file does not use it.
    """
    data = request.get_json(force=True)
    host = data.get("host", "127.0.0.1")
    # ← VULNERABLE: shell=True with user-controlled input
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True, timeout=5)
    return jsonify({"output": result.decode()})


@admin_bp.route("/webhook", methods=["POST"])
@require_auth
def call_webhook():
    """
    ── V-08: CWE-918 Server-Side Request Forgery ─────────────────────────────
    The `url` parameter is fetched server-side without restricting to
    external hosts. An attacker can probe internal services:
    Payload: {"url": "http://169.254.169.254/latest/meta-data/"}
    CodeQL taint: request.json["url"] → requests.get(url)
    """
    data = request.get_json(force=True)
    url  = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL"}), 400
    # ← VULNERABLE: fetches arbitrary URLs including internal/cloud metadata
    resp = http_requests.get(url, timeout=5)
    return jsonify({"status": resp.status_code, "body": resp.text[:2000]})


@admin_bp.route("/users/delete/<int:user_id>", methods=["DELETE"])
@require_auth
def delete_user(user_id: int):
    """
    ── V-16 (sink): CWE-285 Improper Authorization ───────────────────────────
    Role is checked manually but the check is after the operation is set up —
    and can be bypassed if g.role is not set by middleware (e.g. token forgery).
    A non-admin who forges a token with algorithm='none' (V-13) can delete users.
    The cross-file chain is: middleware.py (JWT flaw) → admin.py (role check flaw).
    """
    # ← VULNERABLE: manual role check is bypassable via V-13 JWT flaw
    if g.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    execute_query("DELETE FROM users WHERE id = ?", (user_id,))
    log_action(g.user_id, "delete_user", f"deleted user {user_id}")
    return jsonify({"status": "deleted"})


@admin_bp.route("/run_report", methods=["POST"])
@require_auth
def run_report():
    """
    ── V-19: CWE-209 Information Exposure Through Error Message ─────────────
    Unhandled exceptions propagate full stack traces to the HTTP response.
    Combined with DEBUG=True in config.py, this leaks internal paths,
    library versions, and SQL query strings to any caller.
    """
    data  = request.get_json(force=True)
    query = data.get("query", "")
    # ← VULNERABLE: no try/except — DB errors (with full SQL) returned to client
    rows  = execute_query(query, ())
    return jsonify([dict(r) for r in rows])


@admin_bp.route("/stats")
@require_auth
def system_stats():
    """
    SAFE admin stats. Uses require_admin via require_auth flow and
    only returns aggregate counts — no sensitive data.
    """
    if g.role != "admin":
        return jsonify({"error": "Forbidden"}), 403
    counts = execute_query("SELECT COUNT(*) as n FROM users")[0]["n"]
    txn    = execute_query("SELECT COUNT(*) as n FROM transactions")[0]["n"]
    return jsonify({"users": counts, "transactions": txn})
