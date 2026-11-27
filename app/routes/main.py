"""Primary navigation, awareness, and after-scam routes."""

from flask import Blueprint, jsonify, render_template, request

from app.services.digital_arrest_service import (
    ChecklistValidationError,
    evaluate_call_checklist,
    load_checklist_items,
)

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def home():
    """Render the platform home page."""
    return render_template("home.html")


@main_bp.route("/digital-arrest", methods=["GET", "POST"])
def digital_arrest():
    """Render the digital-arrest awareness page and interactive call checklist."""
    checklist_items = load_checklist_items()
    selected_ids: list[str] = []
    checklist_result = None

    if request.method == "POST":
        selected_ids = request.form.getlist("signs")
        checklist_result = evaluate_call_checklist(selected_ids)

    return render_template(
        "digital_arrest.html",
        checklist_items=checklist_items,
        selected_ids=set(selected_ids),
        checklist_result=checklist_result,
    )


@main_bp.post("/api/digital-arrest-checklist")
def api_digital_arrest_checklist():
    """JSON endpoint for stateless digital-arrest call checklist evaluation."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400
    try:
        result = evaluate_call_checklist(payload.get("signs", []))
    except ChecklistValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result), 200


@main_bp.get("/after-scam")
def after_scam():
    """Render the calm, ordered after-scam assistance page."""
    return render_template("after_scam.html")


@main_bp.get("/android-guide")
def android_guide():
    """Render the Android special-access permissions guidance page."""
    return render_template("android_guide.html")


@main_bp.get("/learning")
def learning():
    """Render the learning lessons, quizzes, and reporting resources page."""
    return render_template("learning.html")


@main_bp.get("/health")
def health():
    """Lightweight health check endpoint for local verification."""
    return jsonify({"status": "ok", "phase": 4})
