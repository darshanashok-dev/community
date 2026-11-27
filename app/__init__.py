"""Flask application factory and core middleware."""

import logging
import time
import uuid

from flask import Flask, g, render_template, request

from config import Config


def _configure_logging(app: Flask) -> None:
    """Configure privacy-aware logging that excludes raw inputs, query strings, and IPs."""
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    handler.setFormatter(formatter)

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    # Suppress default Werkzeug access log lines that include client IPs/query strings
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.setLevel(logging.WARNING)


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_class)

    _configure_logging(app)

    from app.routes import register_blueprints

    register_blueprints(app)

    @app.before_request
    def _start_request_timer() -> None:
        g.request_id = uuid.uuid4().hex[:12]
        g.start_time = time.monotonic()

    @app.after_request
    def _apply_security_headers_and_log(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        response.headers["Cache-Control"] = "no-store"

        elapsed_ms = (time.monotonic() - getattr(g, "start_time", time.monotonic())) * 1000
        req_id = getattr(g, "request_id", "-")
        # Privacy-aware log: path only (no query string, no request body, no client IP)
        app.logger.info(
            "req=%s method=%s path=%s status=%s duration_ms=%.2f",
            req_id,
            request.method,
            request.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    @app.context_processor
    def _inject_global_context() -> dict:
        return {
            "app_name": app.config["APP_NAME"],
            "project_title": app.config["PROJECT_TITLE"],
            "current_phase": 4,
        }

    @app.errorhandler(404)
    def _not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def _internal_error(_error):
        return render_template("errors/500.html"), 500

    return app
