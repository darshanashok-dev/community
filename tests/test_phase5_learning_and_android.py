"""Phase 5 tests: Android permissions guide, static SQLite content store, lessons, and quizzes."""

import sqlite3

import pytest

from app import create_app
from app.database.content_store import (
    get_android_permissions,
    get_lessons,
    get_quiz_questions,
    init_static_content_db,
)
from app.services.learning_service import (
    QuizValidationError,
    evaluate_permission_review,
    grade_quiz,
)
from config import TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def test_sqlite_static_content_store_tables_only(tmp_path):
    db_file = tmp_path / "test_content.db"
    init_static_content_db(db_path=db_file)

    with sqlite3.connect(db_file) as conn:
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert tables == {"android_permissions", "lessons", "quiz_questions"}
    assert len(get_android_permissions(db_path=db_file)) == 4
    assert len(get_lessons(db_path=db_file)) == 6
    assert len(get_quiz_questions(db_path=db_file)) == 8


def test_android_guide_page_and_context_helper(client):
    res = client.get("/android-guide")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    for expected in [
        "Accessibility Access",
        "Notification Access",
        "Display Over Other Apps",
        "Install Unknown Apps",
        "Not APK Malware Classification",
        "How to review or revoke in Android Settings",
    ]:
        assert expected in html

    post_res = client.post(
        "/android-guide",
        data={
            "permissions": ["accessibility", "install_unknown_apps"],
            "app_source": "chat_or_link",
        },
    )
    assert post_res.status_code == 200
    post_html = post_res.get_data(as_text=True)
    assert "Educational Guidance" in post_html
    assert "does not scan APKs" in post_html


def test_permission_review_service_never_labels_malware():
    review = evaluate_permission_review(["accessibility", "notification_access"], "chat_or_link")
    assert len(review["selected_permissions"]) == 2
    assert "never classifies an application as malicious" in review["guidance_points"][0]
    assert "does not scan APKs" in review["disclaimer"]


def test_learning_page_lessons_and_quiz_submission(client):
    res = client.get("/learning")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    for topic in [
        "Phishing Recognition",
        "Suspicious URLs",
        "Digital-Arrest Scams",
        "OTP &amp; Banking Safety",
        "Permission Abuse",
        "Cybercrime Reporting",
        "1930",
        "cybercrime.gov.in",
        "cert-in.org.in",
    ]:
        assert topic in html

    # Submit a mix of right and wrong answers
    post_res = client.post(
        "/learning",
        data={
            "answer_q1": "b",
            "answer_q2": "c",
            "answer_q3": "c",
            "answer_q4": "a",  # wrong
        },
    )
    assert post_res.status_code == 200
    post_html = post_res.get_data(as_text=True)
    assert "Your Score: 3 / 8 (38%)" in post_html
    assert "Retry Quiz" in post_html


def test_quiz_grading_full_score_and_api(client):
    questions = get_quiz_questions()
    all_correct = {q["id"]: q["correct_option"] for q in questions}
    graded = grade_quiz(all_correct)
    assert graded["correct_count"] == 8
    assert graded["total_questions"] == 8
    assert graded["percentage"] == 100

    api_res = client.post("/api/quiz/submit", json={"answers": all_correct})
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert data["percentage"] == 100
    assert data["correct_count"] == 8

    with pytest.raises(QuizValidationError):
        grade_quiz("invalid")  # type: ignore[arg-type]
