"""Routes for message and URL analysis pages and APIs."""

from flask import Blueprint, current_app, jsonify, render_template, request

from app.services.message_analyser import (
    SUPPORTED_CHANNELS,
    MessageValidationError,
    analyze_message,
)

analyzer_bp = Blueprint("analyzer", __name__)


@analyzer_bp.route("/message-analyser", methods=["GET", "POST"])
def message_analyser():
    """Render and handle the in-memory phishing & digital-arrest message analyser."""
    max_length = current_app.config["MAX_MESSAGE_LENGTH"]
    selected_channel = "sms"
    error_message = None
    result = None

    if request.method == "POST":
        selected_channel = (request.form.get("channel") or "sms").strip().lower()
        raw_message = request.form.get("message", "")
        try:
            result = analyze_message(
                raw_text=raw_message,
                channel=selected_channel,
                max_length=max_length,
            )
            # Raw message is not retained or re-rendered after transient analysis
            raw_message = ""
        except MessageValidationError as exc:
            error_message = str(exc)
            if selected_channel not in SUPPORTED_CHANNELS:
                selected_channel = "sms"

    status_code = 400 if error_message else 200
    return (
        render_template(
            "message_analyser.html",
            max_message_length=max_length,
            selected_channel=selected_channel,
            error_message=error_message,
            result=result,
        ),
        status_code,
    )


@analyzer_bp.post("/api/analyze-message")
def api_analyze_message():
    """JSON endpoint for transient in-memory message analysis."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400

    max_length = current_app.config["MAX_MESSAGE_LENGTH"]
    try:
        result = analyze_message(
            raw_text=payload.get("message"),
            channel=payload.get("channel", "sms"),
            max_length=max_length,
        )
    except MessageValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(result), 200


@analyzer_bp.get("/url-analyser")
def url_analyser():
    """Render the text-only URL analyser page."""
    return render_template(
        "url_analyser.html",
        max_url_length=current_app.config["MAX_URL_LENGTH"],
    )
