"""Primary navigation, awareness, Android guide, learning, and after-scam routes."""

from flask import Blueprint, jsonify, render_template, request

from app.database.content_store import (
    get_android_permissions,
    get_lessons,
    get_quiz_questions,
)
from app.services.digital_arrest_service import (
    ChecklistValidationError,
    evaluate_call_checklist,
    load_checklist_items,
)
from app.services.learning_service import (
    QuizValidationError,
    evaluate_permission_review,
    grade_quiz,
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


@main_bp.route("/android-guide", methods=["GET", "POST"])
def android_guide():
    """Render the Android special-access permissions guide and context helper."""
    permissions = get_android_permissions()
    selected_perms: list[str] = []
    selected_source = "official_store"
    review_result = None

    if request.method == "POST":
        selected_perms = request.form.getlist("permissions")
        selected_source = (request.form.get("app_source") or "official_store").strip()
        review_result = evaluate_permission_review(
            selected_permissions=selected_perms,
            app_source=selected_source,
        )

    return render_template(
        "android_guide.html",
        permissions=permissions,
        selected_perms=set(selected_perms),
        selected_source=selected_source,
        review_result=review_result,
    )


@main_bp.route("/learning", methods=["GET", "POST"])
def learning():
    """Render short cybersecurity lessons, interactive quiz, and reporting links."""
    lessons = get_lessons()
    questions = get_quiz_questions()
    submitted_answers: dict[str, str] = {}
    quiz_result = None

    if request.method == "POST":
        for q in questions:
            val = request.form.get(f"answer_{q['id']}", "")
            if val:
                submitted_answers[q["id"]] = val
        quiz_result = grade_quiz(submitted_answers)

    return render_template(
        "learning.html",
        lessons=lessons,
        questions=questions,
        submitted_answers=submitted_answers,
        quiz_result=quiz_result,
    )


@main_bp.post("/api/quiz/submit")
def api_quiz_submit():
    """JSON endpoint for stateless quiz grading."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "Invalid JSON payload."}), 400
    try:
        result = grade_quiz(payload.get("answers", {}))
    except QuizValidationError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(result), 200


@main_bp.get("/health")
def health():
    """Lightweight health check endpoint for local verification."""
    return jsonify({"status": "ok", "phase": 7})
