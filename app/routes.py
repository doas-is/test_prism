"""
app/routes.py
Five vulnerabilities injected:

  V1  CWE-89  SQL Injection (explicit, single-file)
  V2  CWE-78  Command Injection (explicit, single-file)
  V3  CWE-22  Path Traversal (explicit, single-file)
  V4  CWE-89  SQL Injection (cross-file: routes → sanitize.clean → db.raw)
  V5  CWE-601 Open Redirect + auth bypass (cross-file: routes → auth.check_token → redirect)
"""
import os, subprocess
from flask import Flask, request, send_file, redirect, jsonify
from db.db import q, raw, init
from app.sanitize import clean
from app import auth

app = Flask(__name__)
init()


# ── V1: CWE-89 SQL Injection (explicit) ──────────────────────────────────────
@app.route("/login", methods=["POST"])
def login():
    u = request.form.get("username", "")
    p = request.form.get("password", "")
    # Direct f-string interpolation into SQL — no parameterization.
    sql = f"SELECT * FROM users WHERE name='{u}' AND password='{p}'"
    rows = raw(sql)
    return jsonify({"ok": bool(rows)})


# ── V2: CWE-78 OS Command Injection (explicit) ───────────────────────────────
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # shell=True with user-controlled host — ; id or && cat /etc/passwd work.
    out = subprocess.check_output(f"ping -c1 {host}", shell=True, timeout=4)
    return out.decode()


# ── V3: CWE-22 Path Traversal (explicit) ─────────────────────────────────────
@app.route("/file")
def get_file():
    name = request.args.get("name", "")
    # No realpath check — ../../etc/passwd reads arbitrary files.
    path = os.path.join("static", name)
    return send_file(path)


# ── V4: CWE-89 Cross-file SQL Injection ──────────────────────────────────────
# Taint chain (3 hops, 2 files):
#   request.args["q"]          → routes.py   (HTTP source)
#   clean(q)                   → sanitize.py (strips ' only — taint survives)
#   "...LIKE '%" + safe + "%'" → routes.py   (SQL string built)
#   raw(sql)                   → db/db.py    (raw execution — sink)
@app.route("/search")
def search():
    q_raw = request.args.get("q", "")
    safe  = clean(q_raw)                        # sanitize.py — false safety
    sql   = f"SELECT * FROM notes WHERE body LIKE '%{safe}%'"
    rows  = raw(sql)                            # db.py — raw sink
    return jsonify([list(r) for r in rows])


# ── V5: CWE-601 Cross-file Open Redirect + auth bypass ───────────────────────
# Taint chain (2 files):
#   request.args["next"]       → routes.py
#   auth.check_token(token)    → auth.py  (accepts alg=none — always True)
#   redirect(next_url)         → routes.py (arbitrary redirect)
# The bypass: forge a JWT with alg=none → check_token returns True →
# redirect to any attacker URL with an authenticated-looking response.
@app.route("/dashboard")
def dashboard():
    token   = request.args.get("token", "")
    next_url = request.args.get("next", "/home")
    if not auth.check_token(token):
        return jsonify({"error": "unauthorized"}), 401
    # Redirect destination is fully user-controlled — no allowlist.
    return redirect(next_url)


# ── Safe endpoint (no vulnerability) ─────────────────────────────────────────
@app.route("/notes/<int:user_id>")
def notes(user_id):
    rows = q("SELECT body FROM notes WHERE user_id = ?", (user_id,))
    return jsonify([r[0] for r in rows])


if __name__ == "__main__":
    app.run(port=5000)
