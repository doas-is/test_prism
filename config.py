"""
Application configuration.
"""
import os

class Config:
    # ── V-06: CWE-798 Hardcoded credentials ──────────────────────────────────
    # Secret key and DB password baked into source — will appear in version control.
    SECRET_KEY        = "s3cr3t_banking_k3y_do_not_share"
    DB_PASSWORD       = "admin123"
    JWT_SECRET        = "jwt_super_secret_2024"

    # ── V-19: CWE-215 Debug mode enabled in production config ────────────────
    DEBUG             = True
    TESTING           = False

    DATABASE          = os.path.join(os.path.dirname(__file__), "bank.db")
    UPLOAD_DIR        = os.path.join(os.path.dirname(__file__), "uploads")
    REPORTS_DIR       = os.path.join(os.path.dirname(__file__), "reports")
    MAX_TRANSFER      = 1_000_000
    LOG_FILE          = "app.log"


class ProductionConfig(Config):
    # Still inherits the hardcoded secret — the override is incomplete.
    DEBUG = False
