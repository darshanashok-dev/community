"""Blueprint registration for application routes."""

from flask import Flask


def register_blueprints(app: Flask) -> None:
    """Register all route blueprints on the Flask app."""
    from app.routes.analyzer import analyzer_bp
    from app.routes.main import main_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(analyzer_bp)
