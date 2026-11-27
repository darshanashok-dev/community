"""Routes for message and URL analysis pages and APIs."""

from typing import Any

from flask import Blueprint, current_app, jsonify, render_template, request

from app.services.message_analyser import (
    SUPPORTED_CHANNELS,
    MessageValidationError,
    analyze_message,
)
from app.services.reputation_client import (
    check_safe_browsing_v5,
    lookup_rdap_domain,
)
from app.services.url_analyser import UrlValidationError, analyze_url_locally

analyzer_bp = Blueprint("analyzer", __name__)


def _run_url_analysis(raw_url: str | None, consent_external: bool) -> dict[str, Any]:
    """Run local URL inspection and optional opt-in privacy-reduced reputation checks."""
    max_length = current_app.config["MAX_URL_LENGTH"]
    local_result = analyze_url_locally(raw_url=raw_url, max_length=max_length)
    sb_payload = local_result.pop("_safe_browsing_payload", {})

    if not consent_external:
        external_result = {
            "consent_granted": False,
            "safe_browsing": {
                "status": "consent_not_given",
                "display_status": "External check not requested",
                "reason": "Explicit user consent is required before sending privacy-reduced hash prefixes.",
                "matches": [],
                "attribution": None,
            },
            "rdap": {
                "status": "consent_not_given",
                "display_status": "External check not requested",
                "reason": "Explicit user consent is required before sending the registrable domain to RDAP.",
            },
        }
    else:
        timeout = current_app.config["EXTERNAL_API_TIMEOUT_SECONDS"]
        api_key = current_app.config["SAFE_BROWSING_API_KEY"]
        rdap_base = current_app.config["RDAP_BASE_URL"]

        if local_result["privacy_reduction"]["safe_browsing_eligible"]:
            sb_res = check_safe_browsing_v5(
                hash_prefixes_b64=sb_payload.get("hash_prefixes_b64", []),
                candidate_full_hashes_b64=sb_payload.get("full_hashes", []),
                api_key=api_key,
                timeout_seconds=timeout,
            )
        else:
            sb_res = {
                "status": "skipped",
                "display_status": "Safe Browsing check skipped",
                "reason": local_result["privacy_reduction"]["skip_reason"],
                "matches": [],
                "attribution": None,
            }

        rdap_res = lookup_rdap_domain(
            registrable_domain=local_result["privacy_reduction"]["registrable_domain"],
            base_url=rdap_base,
            timeout_seconds=timeout,
        )

        external_result = {
            "consent_granted": True,
            "safe_browsing": sb_res,
            "rdap": rdap_res,
        }

    return {
        "local_analysis": local_result,
        "external_reputation": external_result,
    }


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


@analyzer_bp.route("/url-analyser", methods=["GET", "POST"])
def url_analyser():
    """Render and handle the text-only URL analyser and opt-in external checks."""
    max_length = current_app.config["MAX_URL_LENGTH"]
    consent_external = False
    error_message = None
    analysis = None

    if request.method == "POST":
        raw_url = request.form.get("url", "")
        consent_external = request.form.get("consent_external") in {"on", "true", "1", "yes"}
        try:
            analysis = _run_url_analysis(raw_url=raw_url, consent_external=consent_external)
            # Discard raw submitted URL after transient processing
            raw_url = ""
        except UrlValidationError as exc:
            error_message = str(exc)

    status_code = 400 if error_message else 200
    return (
        render_template(
            "url_analyser.html",
            max_url_length=max_length,
            consent_external=consent_external,
            error_message=error_message,
            analysis=analysis,
        ),
        status_code,
    )


@analyzer_bp.post("/api/analyze-url")
def api_analyze_url():
    """JSON endpoint for text-only URL inspection and explicit opt-in reputation checks."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400

    consent_external = bool(payload.get("consent_external", False))
    try:
        analysis = _run_url_analysis(
            raw_url=payload.get("url"),
            consent_external=consent_external,
        )
    except UrlValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify(analysis), 200
