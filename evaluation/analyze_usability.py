"""Aggregate anonymous participant responses from the usability study CSV.

Blocks template placeholder rows (`P01_TEMPLATE`) and unconsented entries so only
genuine voluntary, consent-confirmed participant responses are summarized.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

LIKERT_FIELDS = (
    "digital_comfort_1_to_5",
    "task1_clarity_1_to_5",
    "task2_benign_confidence_1_to_5",
    "task3_url_clarity_1_to_5",
    "task4_checklist_clarity_1_to_5",
    "task5_android_quiz_clarity_1_to_5",
    "overall_ease_1_to_5",
)


class UsabilityValidationError(ValueError):
    """Raised when usability study CSV is missing, empty, or contains invalid entries."""


def _parse_likert(value: str, field_name: str, pid: str) -> int:
    try:
        num = int(value.strip())
    except ValueError as exc:
        raise UsabilityValidationError(
            f"{pid}: field '{field_name}' must be an integer 1..5, got '{value}'."
        ) from exc
    if not (1 <= num <= 5):
        raise UsabilityValidationError(
            f"{pid}: field '{field_name}' out of range 1..5: {num}."
        )
    return num


def summarize_usability_csv(csv_path: Path) -> dict[str, Any]:
    """Validate and compute anonymous aggregate statistics from participant responses."""
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    real_rows = [
        r
        for r in rows
        if (r.get("participant_code") or "").strip()
        and (r.get("participant_code") or "").strip() != "P01_TEMPLATE"
    ]
    if not real_rows:
        raise UsabilityValidationError(
            "No real participant responses found (only blank or P01_TEMPLATE rows present)."
        )

    scores: dict[str, list[int]] = {f: [] for f in LIKERT_FIELDS}
    age_brackets: dict[str, int] = {}
    advisory_understanding: dict[str, int] = {}
    observations: list[str] = []

    for row in real_rows:
        pid = row["participant_code"].strip()
        consent = (row.get("consent_confirmed") or "").strip().lower()
        if consent != "yes":
            raise UsabilityValidationError(
                f"{pid}: consent_confirmed must be 'yes' to include response."
            )

        age = (row.get("age_bracket") or "unspecified").strip()
        age_brackets[age] = age_brackets.get(age, 0) + 1

        adv = (row.get("understands_advisory_disclaimer") or "unspecified").strip().lower()
        advisory_understanding[adv] = advisory_understanding.get(adv, 0) + 1

        for field in LIKERT_FIELDS:
            scores[field].append(_parse_likert(row.get(field, ""), field, pid))

        obs = (row.get("anonymous_observations") or "").strip()
        if obs:
            observations.append(obs)

    mean_scores = {
        field: round(sum(vals) / len(vals), 2) for field, vals in scores.items()
    }

    return {
        "participant_count": len(real_rows),
        "target_range": "20-30",
        "meets_target_sample_size": len(real_rows) >= 20,
        "age_brackets": age_brackets,
        "advisory_disclaimer_understanding": advisory_understanding,
        "mean_likert_scores_1_to_5": mean_scores,
        "observation_count": len(observations),
        "anonymous_observations": observations,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize anonymous voluntary usability study responses."
    )
    parser.add_argument("--input", required=True, type=Path, help="Completed usability CSV path.")
    parser.add_argument("--output-json", type=Path, default=None, help="Optional JSON output path.")
    args = parser.parse_args()

    try:
        summary = summarize_usability_csv(args.input)
    except UsabilityValidationError as exc:
        print(f"USABILITY SUMMARY BLOCKED:\n{exc}", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(summary, indent=2))
    if args.output_json:
        args.output_json.write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
