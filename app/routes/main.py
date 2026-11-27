"""Primary navigation and awareness routes."""

from flask import Blueprint, jsonify, render_template

main_bp = Blueprint("main", __name__)


@main_bp.get("/")
def home():
    """Render the platform home page."""
    return render_template("home.html")


@main_bp.get("/digital-arrest")
def digital_arrest():
    """Render the digital-arrest awareness page."""
    return render_template("digital_arrest.html")


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
    return jsonify({"status": "ok", "phase": 2})
