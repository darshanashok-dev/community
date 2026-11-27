"""Interactive Digital-Arrest Call Checklist evaluator (stateless, in-memory only)."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

DEFAULT_CHECKLIST_PATH = (
    Path(__file__).resolve().parent.parent / "database" / "digital_arrest_checklist.json"
)


class ChecklistValidationError(ValueError):
    """Raised when invalid checklist input is submitted."""


@lru_cache(maxsize=2)
def load_checklist_items(
    checklist_path: Path = DEFAULT_CHECKLIST_PATH,
) -> tuple[dict[str, Any], ...]:
    with checklist_path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    return tuple(data["checklist_items"])


def evaluate_call_checklist(
    selected_ids: list[str],
    checklist_path: Path = DEFAULT_CHECKLIST_PATH,
) -> dict[str, Any]:
    """Evaluate selected call warning signs and return calm advisory guidance."""
    items = load_checklist_items(checklist_path)
    items_by_id = {item["id"]: item for item in items}

    if not isinstance(selected_ids, list):
        raise ChecklistValidationError("Invalid checklist selection format.")

    clean_selected: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw_id in selected_ids:
        if not isinstance(raw_id, str):
            continue
        item_id = raw_id.strip()
        if item_id in items_by_id and item_id not in seen:
            seen.add(item_id)
            clean_selected.append(items_by_id[item_id])

    count = len(clean_selected)
    has_critical = any(item["severity"] == "critical" for item in clean_selected)

    if count == 0:
        level = "none_selected"
        badge_kind = "info"
        headline = "No warning signs were selected"
        summary = (
            "You did not tick any warning signs from the checklist. "
            "If a call or message still feels unusual, stressful, or rushed, treat that hesitation seriously "
            "and verify independently before acting."
        )
        immediate_steps = [
            "Never act under time pressure from an unexpected caller.",
            "Confirm claims directly with family, your bank's official helpline, or your local police station.",
        ]
    elif count >= 2 or has_critical:
        level = "strong_digital_arrest_pattern"
        badge_kind = "urgent"
        headline = "Strong Digital-Arrest Coercion Pattern Detected"
        summary = (
            "The warning signs you selected match documented digital-arrest impersonation scams. "
            "Genuine Indian police, CBI, customs, RBI, and courts never detain citizens on video calls, "
            "demand secrecy from family, or ask for transfers into 'safe' or 'verification' accounts."
        )
        immediate_steps = [
            "Hang up or close the video call immediately—do not stay on the line out of politeness or fear.",
            "Tell a trusted family member, friend, or your local police station right away.",
            "Do not transfer money, scan QR codes, or share OTPs/PINs.",
            "If you have already transferred funds or shared credentials, call 1930 immediately and follow the After-Scam Assistance steps.",
        ]
    else:
        level = "warning_signs_present"
        badge_kind = "caution"
        headline = "Warning Sign Identified — Pause and Verify Independently"
        summary = (
            "Even a single impersonation, fear, or credential request is a serious warning sign. "
            "Legitimate authorities and banks never object when you pause to verify through official channels."
        )
        immediate_steps = [
            "End the call and look up the official number independently rather than calling back any number given by the caller.",
            "Do not share OTPs, Aadhaar/PAN photos, or remote access to your phone.",
            "Speak with someone you trust before taking any action.",
        ]

    return {
        "selected_count": count,
        "selected_items": clean_selected,
        "level": level,
        "badge_kind": badge_kind,
        "headline": headline,
        "summary": summary,
        "immediate_steps": immediate_steps,
        "show_after_scam_cta": count > 0,
        "advisory_note": (
            "Advisory guidance only: your checklist selections were evaluated in memory and were not saved."
        ),
    }
