"""
app/__init__.py
Flask application factory.
"""
from flask import Flask
from config import Config
from db.database import init_db


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register blueprints
    from app.auth         import auth_bp
    from app.users        import users_bp
    from app.transactions import transactions_bp
    from app.reports      import reports_bp
    from app.admin        import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(transactions_bp)
    app.register_blueprint(reports_bp)
    app.register_blueprint(admin_bp)

    with app.app_context():
        init_db()

    return app
