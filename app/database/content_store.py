"""Static content storage using SQLite seeded from JSON definitions.

Privacy guarantee:
- Stores ONLY static educational content (Android permissions, lessons, quiz questions).
- Never creates tables for, stores, or logs submitted user messages, URLs, or personal data.
- Uses parameterized SQL queries exclusively.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

DATABASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB_PATH = DATABASE_DIR / "content.db"
ANDROID_JSON_PATH = DATABASE_DIR / "android_permissions.json"
LEARNING_JSON_PATH = DATABASE_DIR / "learning_content.json"


def init_static_content_db(
    db_path: Path = DEFAULT_DB_PATH,
    android_json_path: Path = ANDROID_JSON_PATH,
    learning_json_path: Path = LEARNING_JSON_PATH,
) -> Path:
    """Create/sync static SQLite tables from JSON educational content using parameterized SQL."""
    with android_json_path.open("r", encoding="utf-8") as fh:
        android_data = json.load(fh)
    with learning_json_path.open("r", encoding="utf-8") as fh:
        learning_data = json.load(fh)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS android_permissions (
                id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL,
                name TEXT NOT NULL,
                what_it_does TEXT NOT NULL,
                legitimate_uses_json TEXT NOT NULL,
                potential_abuse_json TEXT NOT NULL,
                precautions_json TEXT NOT NULL,
                android_settings_path TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lessons (
                id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL,
                title TEXT NOT NULL,
                topic TEXT NOT NULL,
                summary TEXT NOT NULL,
                fictional_scenario TEXT NOT NULL,
                key_takeaways_json TEXT NOT NULL,
                related_endpoint TEXT NOT NULL,
                related_label TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS quiz_questions (
                id TEXT PRIMARY KEY,
                sort_order INTEGER NOT NULL,
                topic TEXT NOT NULL,
                question TEXT NOT NULL,
                options_json TEXT NOT NULL,
                correct_option TEXT NOT NULL,
                explanation TEXT NOT NULL
            )
            """
        )

        # Refresh static content deterministically
        conn.execute("DELETE FROM android_permissions")
        for idx, perm in enumerate(android_data["permissions"]):
            conn.execute(
                """
                INSERT INTO android_permissions (
                    id, sort_order, name, what_it_does,
                    legitimate_uses_json, potential_abuse_json,
                    precautions_json, android_settings_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    perm["id"],
                    idx,
                    perm["name"],
                    perm["what_it_does"],
                    json.dumps(perm["legitimate_uses"]),
                    json.dumps(perm["potential_abuse"]),
                    json.dumps(perm["precautions"]),
                    perm["android_settings_path"],
                ),
            )

        conn.execute("DELETE FROM lessons")
        for idx, lesson in enumerate(learning_data["lessons"]):
            conn.execute(
                """
                INSERT INTO lessons (
                    id, sort_order, title, topic, summary,
                    fictional_scenario, key_takeaways_json,
                    related_endpoint, related_label
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lesson["id"],
                    idx,
                    lesson["title"],
                    lesson["topic"],
                    lesson["summary"],
                    lesson["fictional_scenario"],
                    json.dumps(lesson["key_takeaways"]),
                    lesson["related_endpoint"],
                    lesson["related_label"],
                ),
            )

        conn.execute("DELETE FROM quiz_questions")
        for idx, q in enumerate(learning_data["quiz_questions"]):
            conn.execute(
                """
                INSERT INTO quiz_questions (
                    id, sort_order, topic, question,
                    options_json, correct_option, explanation
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    q["id"],
                    idx,
                    q["topic"],
                    q["question"],
                    json.dumps(q["options"]),
                    q["correct_option"],
                    q["explanation"],
                ),
            )

        conn.commit()
    return db_path


def _connect_readonly(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    if not db_path.exists():
        init_static_content_db(db_path=db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def get_android_permissions(db_path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    with _connect_readonly(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, name, what_it_does, legitimate_uses_json,
                   potential_abuse_json, precautions_json, android_settings_path
            FROM android_permissions
            ORDER BY sort_order ASC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "what_it_does": row["what_it_does"],
            "legitimate_uses": json.loads(row["legitimate_uses_json"]),
            "potential_abuse": json.loads(row["potential_abuse_json"]),
            "precautions": json.loads(row["precautions_json"]),
            "android_settings_path": row["android_settings_path"],
        }
        for row in rows
    ]


def get_lessons(db_path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    with _connect_readonly(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, title, topic, summary, fictional_scenario,
                   key_takeaways_json, related_endpoint, related_label
            FROM lessons
            ORDER BY sort_order ASC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "title": row["title"],
            "topic": row["topic"],
            "summary": row["summary"],
            "fictional_scenario": row["fictional_scenario"],
            "key_takeaways": json.loads(row["key_takeaways_json"]),
            "related_endpoint": row["related_endpoint"],
            "related_label": row["related_label"],
        }
        for row in rows
    ]


def get_quiz_questions(db_path: Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    with _connect_readonly(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, topic, question, options_json, correct_option, explanation
            FROM quiz_questions
            ORDER BY sort_order ASC
            """
        ).fetchall()
    return [
        {
            "id": row["id"],
            "topic": row["topic"],
            "question": row["question"],
            "options": json.loads(row["options_json"]),
            "correct_option": row["correct_option"],
            "explanation": row["explanation"],
        }
        for row in rows
    ]
