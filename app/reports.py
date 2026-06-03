"""
app/reports.py
Account report generation and file download endpoints.
"""
import os
from flask import Blueprint, request, jsonify, send_file, Response
from db.database import execute_query, execute_raw
from app.middleware import require_auth
from app.utils import weak_sanitize
from config import Config

reports_bp = Blueprint("reports", __name__, url_prefix="/reports")


@reports_bp.route("/summary")
@require_auth
def account_summary():
    """
    ── V-03: CWE-79 Cross-Site Scripting (Reflected XSS) ────────────────────
    The `format` query parameter is reflected directly into an HTML response
    body without encoding. An attacker can inject script tags via the URL.
    Payload: /reports/summary?format=<script>alert(document.cookie)</script>
    CodeQL taint: request.args → fmt → Response(html=...)
    """
    fmt  = request.args.get("format", "json")
    # ← VULNERABLE: user input embedded in HTML without escaping
    html = f"<html><body><h1>Report format: {fmt}</h1></body></html>"
    return Response(html, mimetype="text/html")


@reports_bp.route("/download")
@require_auth
def download_report():
    """
    ── V-04: CWE-22 Path Traversal ──────────────────────────────────────────
    The `filename` parameter is joined directly to the reports directory
    without normalization or validation. An attacker can read arbitrary files.
    Payload: /reports/download?filename=../../config.py
    CodeQL taint: request.args["filename"] → os.path.join → send_file()
    """
    filename = request.args.get("filename", "")
    # ← VULNERABLE: no os.path.realpath / prefix check
    filepath = os.path.join(Config.REPORTS_DIR, filename)
    if not os.path.isfile(filepath):
        return jsonify({"error": "File not found"}), 404
    return send_file(filepath)


@reports_bp.route("/search_transactions")
@require_auth
def search_transactions():
    """
    ── V-11: CWE-89 Second-order / cross-file SQL Injection ─────────────────
    Taint chain:
      request.args["desc"]          (source)
      → weak_sanitize(desc)         (utils.py — strips ' only)
      → SQL string built here
      → execute_raw(sql)            (database.py — raw exec, two hops)

    This mirrors V-02 but in a different module, demonstrating that the
    same weak_sanitize → execute_raw taint path exists in multiple places.
    The DL layer should detect the taint regardless of which file it flows through.
    """
    desc     = request.args.get("desc", "")
    clean    = weak_sanitize(desc)
    sql      = (
        f"SELECT * FROM transactions "
        f"WHERE description LIKE \"%{clean}%\" "
        f"ORDER BY created_at DESC LIMIT 100"
    )
    rows = execute_raw(sql)
    return jsonify([dict(r) for r in rows])


@reports_bp.route("/export")
@require_auth
def export_safe():
    """
    SAFE export: uses parameterized query and validates the output format.
    """
    allowed_formats = {"csv", "json"}
    fmt = request.args.get("format", "json")
    if fmt not in allowed_formats:
        return jsonify({"error": "Invalid format"}), 400

    rows = execute_query(
        "SELECT id, amount, created_at FROM transactions WHERE from_user = ? LIMIT 1000",
        (g.user_id,),
    )
    if fmt == "json":
        return jsonify([dict(r) for r in rows])
    # csv output (safe — no user data in headers)
    lines = ["id,amount,date"] + [f"{r['id']},{r['amount']},{r['created_at']}" for r in rows]
    return Response("\n".join(lines), mimetype="text/csv")
