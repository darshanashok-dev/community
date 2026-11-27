"""Flask application factory and core privacy/security middleware."""

import logging
import time
import uuid

from flask import Flask, g, jsonify, render_template, request

from app.services.rate_limiter import InMemoryRateLimiter
from config import Config


def _configure_logging(app: Flask) -> None:
    """Configure privacy-aware logging that excludes raw inputs, query strings, and IPs."""
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(formatter)

    app.logger.handlers.clear()
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.propagate = False

    # Suppress default Werkzeug access log lines that include client IPs/query strings
    werkzeug_logger = logging.getLogger("werkzeug")
    werkzeug_logger.setLevel(logging.WARNING)


def _error_response(status_code: int, title: str, message: str, extra_headers: dict[str, str] | None = None):
    if request.path.startswith("/api/"):
        resp = jsonify({"error": message})
        resp.status_code = status_code
    else:
        resp = app_render_error(status_code, title, message)
    if extra_headers:
        for k, v in extra_headers.items():
            resp.headers[k] = v
    return resp


def app_render_error(status_code: int, title: str, message: str):
    return (
        render_template("errors/generic.html", error_title=title, error_message=message),
        status_code,
    )


def create_app(config_class: type[Config] = Config) -> Flask:
    """Create and configure the Flask application instance."""
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )
    app.config.from_object(config_class)

    _configure_logging(app)

    from app.database.content_store import init_static_content_db
    from app.routes import register_blueprints

    init_static_content_db()
    register_blueprints(app)

    rate_limiter = InMemoryRateLimiter(
        max_requests=app.config.get("RATE_LIMIT_REQUESTS_PER_MINUTE", 60),
        window_seconds=60,
    )
    app.extensions["rate_limiter"] = rate_limiter

    @app.before_request
    def _start_request_timer_and_rate_limit():
        g.request_id = uuid.uuid4().hex[:12]
        g.start_time = time.monotonic()

        if app.config.get("RATE_LIMIT_ENABLED", True) and request.method == "POST":
            client_id = request.remote_addr or "local"
            allowed, retry_after = rate_limiter.allow(client_id)
            if not allowed:
                return _error_response(
                    429,
                    "Too Many Requests (429)",
                    "Too many submissions in a short period. Please wait a moment before trying again.",
                    extra_headers={"Retry-After": str(retry_after)},
                )
        return None

    @app.after_request
    def _apply_security_headers_and_log(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
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
            "current_phase": 6,
        }

    @app.errorhandler(400)
    def _bad_request(_error):
        return _error_response(
            400,
            "Invalid Request (400)",
            "The submitted request could not be processed. Please verify your input and try again.",
        )

    @app.errorhandler(404)
    def _not_found(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Endpoint not found."}), 404
        return render_template("errors/404.html"), 404

    @app.errorhandler(405)
    def _method_not_allowed(_error):
        return _error_response(
            405,
            "Method Not Allowed (405)",
            "This request method is not supported for this address.",
        )

    @app.errorhandler(413)
    def _payload_too_large(_error):
        return _error_response(
            413,
            "Submission Too Large (413)",
            "The submitted content exceeds the maximum allowed request size.",
        )

    @app.errorhandler(500)
    def _internal_error(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "An unexpected server error occurred."}), 500
        return render_template("errors/500.html"), 500

    return app
