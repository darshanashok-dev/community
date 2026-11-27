"""Business logic for Android permission guidance and cybersecurity quiz scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.database.content_store import (
    DEFAULT_DB_PATH,
    get_android_permissions,
    get_quiz_questions,
)


class QuizValidationError(ValueError):
    """Raised when quiz submission data is malformed."""


def evaluate_permission_review(
    selected_permissions: list[str],
    app_source: str = "official_store",
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Provide non-diagnostic educational guidance for selected Android permissions.

    Strictly educational: never claims permission presence proves an app is malicious.
    """
    all_perms = get_android_permissions(db_path=db_path)
    perms_by_id = {p["id"]: p for p in all_perms}
    selected = [perms_by_id[pid] for pid in selected_permissions if pid in perms_by_id]

    valid_sources = {"official_store", "chat_or_link", "unsure"}
    source = app_source if app_source in valid_sources else "unsure"

    guidance_points: list[str] = [
        "Permission presence alone never classifies an application as malicious or safe.",
    ]

    if source == "chat_or_link":
        guidance_points.append(
            "An APK file received via WhatsApp, SMS, or an unsolicited link bypasses official app-store screening—verify independently before installing or granting any special access."
        )
    elif source == "unsure":
        guidance_points.append(
            "Check Android App Info to confirm where the app was installed from, and verify whether the requested permission matches the app's stated purpose."
        )
    else:
        guidance_points.append(
            "Even for store-installed apps, ask whether the app genuinely needs each sensitive permission for its core feature."
        )

    if selected:
        guidance_points.append(
            f"You selected {len(selected)} sensitive permission(s). Review each Settings path below if you did not expect the app to ask for that access."
        )

    return {
        "selected_permissions": selected,
        "source": source,
        "guidance_points": guidance_points,
        "disclaimer": (
            "Educational guidance only: this tool does not scan APKs, inspect device apps, or classify software as malware."
        ),
    }


def grade_quiz(
    submitted_answers: dict[str, str],
    db_path: Path = DEFAULT_DB_PATH,
) -> dict[str, Any]:
    """Grade multiple-choice quiz answers against static SQLite quiz questions."""
    if not isinstance(submitted_answers, dict):
        raise QuizValidationError("Quiz answers must be provided as a question-to-option mapping.")

    questions = get_quiz_questions(db_path=db_path)
    total = len(questions)
    correct_count = 0
    answered_count = 0
    results: list[dict[str, Any]] = []

    for q in questions:
        qid = q["id"]
        chosen_raw = submitted_answers.get(qid)
        chosen = chosen_raw.strip() if isinstance(chosen_raw, str) else ""
        option_map = {opt["id"]: opt["text"] for opt in q["options"]}
        if chosen not in option_map:
            chosen = ""
        else:
            answered_count += 1

        is_correct = chosen == q["correct_option"]
        if is_correct:
            correct_count += 1

        results.append(
            {
                "id": qid,
                "topic": q["topic"],
                "question": q["question"],
                "chosen_option": chosen,
                "chosen_text": option_map.get(chosen, "No answer selected"),
                "correct_option": q["correct_option"],
                "correct_text": option_map.get(q["correct_option"], ""),
                "is_correct": is_correct,
                "explanation": q["explanation"],
            }
        )

    percentage = round((correct_count / total) * 100) if total > 0 else 0
    if percentage >= 80:
        feedback = "Strong grasp of practical phishing, URL, digital-arrest, and Android permission safety concepts."
        badge_kind = "calm"
    elif percentage >= 50:
        feedback = "Good progress. Review the explanations for missed scenarios below and try again."
        badge_kind = "caution"
    else:
        feedback = "Good starting check—read the short lessons above and retry the quiz to reinforce key warning signs."
        badge_kind = "info"

    return {
        "total_questions": total,
        "answered_count": answered_count,
        "correct_count": correct_count,
        "percentage": percentage,
        "badge_kind": badge_kind,
        "feedback": feedback,
        "question_results": results,
    }
