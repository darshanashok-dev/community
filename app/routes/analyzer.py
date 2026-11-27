"""Routes for message and URL analysis pages."""

from flask import Blueprint, current_app, render_template

analyzer_bp = Blueprint("analyzer", __name__)


@analyzer_bp.get("/message-analyser")
def message_analyser():
    """Render the phishing and digital-arrest message analyser page."""
    return render_template(
        "message_analyser.html",
        max_message_length=current_app.config["MAX_MESSAGE_LENGTH"],
    )


@analyzer_bp.get("/url-analyser")
def url_analyser():
    """Render the text-only URL analyser page."""
    return render_template(
        "url_analyser.html",
        max_url_length=current_app.config["MAX_URL_LENGTH"],
    )
