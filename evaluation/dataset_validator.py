"""Strict validation helpers for detection evaluation datasets.

Enforces provenance (`synthetic_dev` vs `genuine_eval`), source/license metadata,
two-annotator completeness, PII redaction checks, and minimum sample thresholds
before genuine held-out evaluation can run.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REQUIRED_COLUMNS = (
    "sample_id",
    "dataset_origin",
    "source_type",
    "source_provenance",
    "license_or_permission",
    "template_group_id",
    "channel",
    "redacted_text",
    "annotator_1_label",
    "annotator_2_label",
    "adjudicated_label",
    "disagreement_notes",
)

VALID_ORIGINS = frozenset({"synthetic_dev", "genuine_eval"})
VALID_LABELS = frozenset({"scam", "benign"})
VALID_CHANNELS = frozenset({"sms", "whatsapp", "email"})
BENIGN_TRANSACTIONAL_TYPES = frozenset(
    {
        "bank_alert",
        "upi_alert",
        "delivery_alert",
        "benign_bank",
        "benign_upi",
        "benign_delivery",
    }
)

# Unredacted PII detectors (real-looking addresses/numbers that should be masked)
_RAW_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_RAW_PHONE_RE = re.compile(r"(?<!\d)(?:\+?91[- ]?)?[6-9]\d{9}(?!\d)")
_RAW_AADHAAR_RE = re.compile(r"\b\d{4}[ -]\d{4}[ -]\d{4}\b")
_RAW_PAN_RE = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")


class DatasetValidationError(ValueError):
    """Raised when a dataset fails provenance, redaction, annotation, or size checks."""


@dataclass(frozen=True)
class ValidationSummary:
    mode: str
    total_rows: int
    genuine_rows: int
    synthetic_rows: int
    benign_transactional_rows: int
    class_counts: dict[str, int]
    origins: dict[str, int]


def find_unredacted_pii(text: str) -> list[str]:
    """Return a list of PII categories suspected in text (without returning the raw values)."""
    findings: list[str] = []
    if _RAW_EMAIL_RE.search(text):
        findings.append("email_address")
    if _RAW_PHONE_RE.search(text):
        findings.append("indian_mobile_number")
    if _RAW_AADHAAR_RE.search(text):
        findings.append("aadhaar_like_12_digits")
    if _RAW_PAN_RE.search(text):
        findings.append("pan_like_identifier")
    return findings


def validate_dataset_rows(
    rows: list[dict[str, str]],
    fieldnames: list[str] | None = None,
    mode: str = "genuine-eval",
    allow_synthetic_only: bool = False,
) -> ValidationSummary:
    """Validate dataset schema, provenance, annotations, redaction, and thresholds."""
    if mode not in {"genuine-eval", "synthetic-smoke"}:
        raise DatasetValidationError(
            f"Unsupported validation mode '{mode}'. Use 'genuine-eval' or 'synthetic-smoke'."
        )

    if fieldnames is not None:
        missing_cols = [col for col in REQUIRED_COLUMNS if col not in fieldnames]
        if missing_cols:
            raise DatasetValidationError(
                f"CSV is missing required columns: {', '.join(missing_cols)}"
            )

    if not rows:
        raise DatasetValidationError("Dataset CSV contains no rows.")

    errors: list[str] = []
    seen_ids: set[str] = set()
    origins: dict[str, int] = {}
    class_counts = {"scam": 0, "benign": 0}
    benign_transactional = 0

    for idx, row in enumerate(rows, start=2):
        sid = (row.get("sample_id") or "").strip()
        if not sid:
            errors.append(f"Row {idx}: missing sample_id.")
            continue
        if sid in seen_ids:
            errors.append(f"Row {idx}: duplicate sample_id '{sid}'.")
        seen_ids.add(sid)

        origin = (row.get("dataset_origin") or "").strip()
        if origin not in VALID_ORIGINS:
            errors.append(
                f"{sid}: dataset_origin must be 'genuine_eval' or 'synthetic_dev', got '{origin}'."
            )
        else:
            origins[origin] = origins.get(origin, 0) + 1

        if mode == "genuine-eval" and origin != "genuine_eval":
            errors.append(
                f"{sid}: synthetic_dev row is blocked in genuine-eval mode."
            )
        elif mode == "synthetic-smoke" and not allow_synthetic_only and origin != "synthetic_dev":
            errors.append(
                f"{sid}: synthetic-smoke mode accepts synthetic_dev rows only."
            )

        for req_field in ("source_type", "source_provenance", "license_or_permission", "template_group_id"):
            if not (row.get(req_field) or "").strip():
                errors.append(f"{sid}: missing required field '{req_field}'.")

        channel = (row.get("channel") or "").strip().lower()
        if channel not in VALID_CHANNELS:
            errors.append(f"{sid}: invalid channel '{channel}'.")

        text = (row.get("redacted_text") or "").strip()
        if not text:
            errors.append(f"{sid}: redacted_text cannot be empty.")
        else:
            pii_hits = find_unredacted_pii(text)
            if pii_hits:
                errors.append(
                    f"{sid}: potential unredacted PII detected ({', '.join(pii_hits)}). Redact before evaluation."
                )

        a1 = (row.get("annotator_1_label") or "").strip().lower()
        a2 = (row.get("annotator_2_label") or "").strip().lower()
        adj = (row.get("adjudicated_label") or "").strip().lower()
        if a1 not in VALID_LABELS:
            errors.append(f"{sid}: invalid annotator_1_label '{a1}'.")
        if a2 not in VALID_LABELS:
            errors.append(f"{sid}: invalid annotator_2_label '{a2}'.")
        if adj not in VALID_LABELS:
            errors.append(f"{sid}: invalid adjudicated_label '{adj}'.")
        else:
            class_counts[adj] += 1

        if a1 in VALID_LABELS and a2 in VALID_LABELS and a1 != a2:
            if not (row.get("disagreement_notes") or "").strip():
                errors.append(
                    f"{sid}: annotator_1_label != annotator_2_label requires disagreement_notes."
                )

        src_type = (row.get("source_type") or "").strip().lower()
        if adj == "benign" and src_type in BENIGN_TRANSACTIONAL_TYPES:
            benign_transactional += 1

    genuine_count = origins.get("genuine_eval", 0)
    synthetic_count = origins.get("synthetic_dev", 0)

    if mode == "genuine-eval":
        if genuine_count < 300:
            errors.append(
                f"Genuine dataset threshold unmet: found {genuine_count} genuine_eval rows, minimum 300 required."
            )
        if benign_transactional < 100:
            errors.append(
                f"Genuine benign transactional threshold unmet: found {benign_transactional} benign bank/UPI/delivery rows, minimum 100 required."
            )

    if errors:
        preview = "\n - ".join(errors[:15])
        more = f"\n ... and {len(errors) - 15} more issue(s)." if len(errors) > 15 else ""
        raise DatasetValidationError(f"Dataset validation failed:\n - {preview}{more}")

    return ValidationSummary(
        mode=mode,
        total_rows=len(rows),
        genuine_rows=genuine_count,
        synthetic_rows=synthetic_count,
        benign_transactional_rows=benign_transactional,
        class_counts=class_counts,
        origins=origins,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate dataset provenance, redaction, annotations, and sample thresholds."
    )
    parser.add_argument("--input", required=True, type=Path, help="Path to labelled CSV file.")
    parser.add_argument(
        "--mode",
        choices=["genuine-eval", "synthetic-smoke"],
        default="genuine-eval",
        help="Validation mode (default: genuine-eval).",
    )
    args = parser.parse_args()

    with args.input.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    try:
        summary = validate_dataset_rows(rows, fieldnames=fieldnames, mode=args.mode)
    except DatasetValidationError as exc:
        print(f"VALIDATION FAILED:\n{exc}", file=sys.stderr)
        sys.exit(2)

    print(
        f"VALIDATION PASSED ({summary.mode}): total={summary.total_rows}, "
        f"genuine={summary.genuine_rows}, benign_transactional={summary.benign_transactional_rows}, "
        f"classes={summary.class_counts}"
    )


if __name__ == "__main__":
    main()
