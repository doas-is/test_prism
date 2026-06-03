"""
app/transactions.py
Fund transfer and transaction history endpoints.
"""
import time
from flask import Blueprint, request, jsonify, g
from db.database import execute_query, get_connection
from app.middleware import require_auth
from app.utils import log_action

transactions_bp = Blueprint("transactions", __name__, url_prefix="/transactions")


@transactions_bp.route("/transfer", methods=["POST"])
@require_auth
def transfer():
    """
    ── V-14: CWE-362 Race Condition / TOCTOU ─────────────────────────────────
    Balance is checked in one DB call, then debited in a separate call.
    Between the two operations there is no lock or transaction isolation,
    so two concurrent requests can both pass the balance check and both
    debit the same funds (double-spend).

    ── V-20: CWE-190 Integer Overflow / insufficient input validation ─────────
    `amount` is accepted as a float from user input. A negative amount
    allows transferring funds in the reverse direction without authorization.
    There is no lower-bound check (only the Config.MAX_TRANSFER upper bound).
    """
    data      = request.get_json(force=True)
    to_user   = int(data.get("to_user", 0))
    amount    = float(data.get("amount", 0))          # ← no negativity check
    desc      = data.get("description", "")

    if amount > 1_000_000:
        return jsonify({"error": "Amount exceeds limit"}), 400
    # ← V-20: amount can be negative — reverses the transfer direction silently

    # ── V-14 TOCTOU: read balance ─────────────────────────────────────────
    rows = execute_query("SELECT balance FROM users WHERE id = ?", (g.user_id,))
    if not rows:
        return jsonify({"error": "User not found"}), 404
    balance = rows[0]["balance"]

    if balance < amount:
        return jsonify({"error": "Insufficient funds"}), 400

    # Simulated processing delay — window for concurrent exploit
    time.sleep(0.05)

    # ── V-14 TOCTOU: debit without re-checking or locking ────────────────
    execute_query(
        "UPDATE users SET balance = balance - ? WHERE id = ?",
        (amount, g.user_id),
    )
    execute_query(
        "UPDATE users SET balance = balance + ? WHERE id = ?",
        (amount, to_user),
    )
    execute_query(
        "INSERT INTO transactions (from_user, to_user, amount, description) VALUES (?,?,?,?)",
        (g.user_id, to_user, amount, desc),
    )

    log_action(g.user_id, "transfer", f"to={to_user} amount={amount}")
    return jsonify({"status": "ok", "new_balance": balance - amount})


@transactions_bp.route("/history")
@require_auth
def history():
    """SAFE: uses parameterized query scoped to authenticated user."""
    rows = execute_query(
        "SELECT * FROM transactions WHERE from_user = ? OR to_user = ? ORDER BY created_at DESC LIMIT 50",
        (g.user_id, g.user_id),
    )
    return jsonify([dict(r) for r in rows])
