"""In-memory contextual phishing and digital-arrest message analysis engine.

Privacy contract:
- Processes message text strictly in memory.
- Never writes submitted text to disk, database, or logs.
- Never transmits submitted text to external services.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

SUPPORTED_CHANNELS = frozenset({"sms", "whatsapp", "email"})
DEFAULT_RULES_PATH = Path(__file__).resolve().parent.parent / "database" / "message_rules.json"


class MessageValidationError(ValueError):
    """Raised when submitted message input fails validation."""


@dataclass(frozen=True)
class CompiledRule:
    rule_id: str
    title: str
    weight: int
    patterns: tuple[re.Pattern[str], ...]
    negative_patterns: tuple[re.Pattern[str], ...]
    skip_if_matched: frozenset[str]
    skip_if_benign: frozenset[str]
    why_it_matters: str
    category_tag: str


@dataclass(frozen=True)
class CompiledBenignContext:
    context_id: str
    title: str
    offset: int
    patterns: tuple[re.Pattern[str], ...]
    blocked_by: frozenset[str]
    explanation: str


@lru_cache(maxsize=4)
def load_rules_config(rules_path: Path = DEFAULT_RULES_PATH) -> dict[str, Any]:
    """Load and compile rule definitions from JSON configuration."""
    with rules_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)

    compiled_rules: list[CompiledRule] = []
    for item in raw["rules"]:
        compiled_rules.append(
            CompiledRule(
                rule_id=item["id"],
                title=item["title"],
                weight=int(item["weight"]),
                patterns=tuple(re.compile(p, re.IGNORECASE) for p in item["patterns"]),
                negative_patterns=tuple(
                    re.compile(p, re.IGNORECASE) for p in item.get("negative_patterns", [])
                ),
                skip_if_matched=frozenset(item.get("skip_if_matched", [])),
                skip_if_benign=frozenset(item.get("skip_if_benign", [])),
                why_it_matters=item["why_it_matters"],
                category_tag=item["category_tag"],
            )
        )

    compiled_benign: list[CompiledBenignContext] = []
    for item in raw.get("benign_contexts", []):
        compiled_benign.append(
            CompiledBenignContext(
                context_id=item["id"],
                title=item["title"],
                offset=int(item["offset"]),
                patterns=tuple(re.compile(p, re.IGNORECASE) for p in item["patterns"]),
                blocked_by=frozenset(item.get("blocked_by", [])),
                explanation=item["explanation"],
            )
        )

    return {
        "version": raw["version"],
        "score_bounds": raw["score_bounds"],
        "categories": raw["categories"],
        "rules": tuple(compiled_rules),
        "combinations": tuple(raw.get("combinations", [])),
        "benign_contexts": tuple(compiled_benign),
    }


_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\ufeff]")


def _normalize_whitespace(text: str) -> str:
    cleaned = _ZERO_WIDTH_RE.sub("", text)
    return re.sub(r"\s+", " ", cleaned).strip()


def _select_category(score: int, categories: list[dict[str, Any]]) -> dict[str, Any]:
    for cat in categories:
        if cat["min_score"] <= score <= cat["max_score"]:
            return cat
    return categories[-1]


def _evaluate_combinations(
    matched_ids: set[str],
    channel: str,
    combinations: tuple[dict[str, Any], ...],
) -> list[dict[str, Any]]:
    triggered: list[dict[str, Any]] = []
    for combo in combinations:
        cid = combo["id"]
        matched = False
        if cid == "combo_digital_arrest":
            req_matches = sum(1 for rid in combo["required_any"] if rid in matched_ids)
            imp_plus = (
                "impersonation" in matched_ids
                and any(rid in matched_ids for rid in combo["or_impersonation_plus_one"])
            )
            matched = req_matches >= combo["min_matches"] or imp_plus
        elif cid == "combo_credential_phishing":
            has_a = any(rid in matched_ids for rid in combo["group_a_any"])
            has_b = any(rid in matched_ids for rid in combo["group_b_any"])
            has_c = any(rid in matched_ids for rid in combo["group_c_any"])
            matched = has_a and has_b and has_c
        elif cid == "combo_unofficial_channel_coercion":
            matched = channel in combo["channels"] and any(
                rid in matched_ids for rid in combo["required_any"]
            )

        if matched:
            triggered.append(
                {
                    "id": cid,
                    "title": combo["title"],
                    "contribution": int(combo["weight"]),
                    "why_it_matters": combo["why_it_matters"],
                    "type": "combination",
                }
            )
    return triggered


def _build_recommended_actions(
    matched_ids: set[str],
    category_id: str,
) -> list[str]:
    actions: list[str] = []

    digital_arrest_signals = {
        "arrest_threat",
        "legal_intimidation",
        "secrecy",
        "video_call_pressure",
        "safe_account",
    }
    if matched_ids & digital_arrest_signals:
        actions.extend(
            [
                "Disconnect the call or stop replying immediately. Indian police, CBI, customs, and courts never conduct 'digital arrests'.",
                "Talk openly with a trusted family member, friend, or your local police station—never comply with demands for secrecy.",
                "Do not transfer funds to any 'RBI verification', 'escrow', or 'safe' account.",
            ]
        )

    if "otp_password_request" in matched_ids or "sensitive_info_request" in matched_ids:
        actions.append(
            "Never share OTPs, UPI PINs, passwords, Aadhaar/PAN photos, or install remote-access apps (such as AnyDesk or TeamViewer) on request."
        )

    if "payment_demand" in matched_ids:
        actions.append(
            "Do not scan unknown QR codes or enter your UPI PIN—a PIN is only for sending money, never for receiving funds."
        )

    if "suspicious_link_or_contact" in matched_ids:
        actions.append(
            "Avoid clicking links or calling phone numbers inside the message; check status directly through your bank's official app or verified website."
        )

    if category_id == "strong_scam_signs":
        actions.append(
            "If you have already shared credentials or transferred money, call 1930 immediately and report at cybercrime.gov.in."
        )
    elif category_id == "some_warning_signs":
        actions.append(
            "Verify independently through an official helpline printed on your bank card or official app before responding."
        )
    else:
        actions.append(
            "Treat 'No known red flags' as advisory only—always verify unexpected requests for money, links, or personal details independently."
        )

    return list(dict.fromkeys(actions))


def analyze_message(
    raw_text: str | None,
    channel: str = "sms",
    max_length: int = 5000,
    rules_path: Path = DEFAULT_RULES_PATH,
) -> dict[str, Any]:
    """Analyse message text transiently in memory and return an explainable advisory dict."""
    if raw_text is None or not isinstance(raw_text, str):
        raise MessageValidationError("Please paste a message to analyse.")

    normalized_channel = (channel or "sms").strip().lower()
    if normalized_channel not in SUPPORTED_CHANNELS:
        raise MessageValidationError(
            "Channel must be one of: sms, whatsapp, or email."
        )

    cleaned_text = _normalize_whitespace(raw_text)
    if not cleaned_text:
        raise MessageValidationError("Message text cannot be empty.")

    if len(raw_text) > max_length:
        raise MessageValidationError(
            f"Message exceeds the maximum allowed length of {max_length} characters."
        )

    config = load_rules_config(rules_path)
    rules: tuple[CompiledRule, ...] = config["rules"]
    benign_contexts: tuple[CompiledBenignContext, ...] = config["benign_contexts"]

    # First pass: check benign context pattern matches (before blocking check)
    candidate_benign: set[str] = set()
    for bctx in benign_contexts:
        if any(p.search(cleaned_text) for p in bctx.patterns):
            candidate_benign.add(bctx.context_id)

    # Evaluate rules in order (strong rules precede isolated/fallback rules)
    matched_rules: list[dict[str, Any]] = []
    matched_ids: set[str] = set()

    for rule in rules:
        if rule.skip_if_matched & matched_ids:
            continue
        if rule.skip_if_benign & candidate_benign:
            continue
        if rule.negative_patterns and any(
            neg.search(cleaned_text) for neg in rule.negative_patterns
        ):
            continue
        if any(p.search(cleaned_text) for p in rule.patterns):
            matched_ids.add(rule.rule_id)
            matched_rules.append(
                {
                    "id": rule.rule_id,
                    "title": rule.title,
                    "contribution": rule.weight,
                    "why_it_matters": rule.why_it_matters,
                    "category_tag": rule.category_tag,
                    "type": "indicator",
                }
            )

    # Evaluate combination bonuses
    matched_combos = _evaluate_combinations(
        matched_ids, normalized_channel, config["combinations"]
    )

    # Filter benign contexts that are not invalidated by coercive/harvesting signals
    applied_benign: list[dict[str, Any]] = []
    for bctx in benign_contexts:
        if bctx.context_id in candidate_benign and not (bctx.blocked_by & matched_ids):
            applied_benign.append(
                {
                    "id": bctx.context_id,
                    "title": bctx.title,
                    "contribution": bctx.offset,
                    "explanation": bctx.explanation,
                }
            )

    raw_indicator_score = sum(item["contribution"] for item in matched_rules)
    combo_score = sum(item["contribution"] for item in matched_combos)
    benign_offset = sum(item["contribution"] for item in applied_benign)

    min_score = int(config["score_bounds"]["min"])
    max_score = int(config["score_bounds"]["max"])
    raw_total = raw_indicator_score + combo_score + benign_offset
    final_score = max(min_score, min(max_score, raw_total))

    # Guardrail: an isolated keyword without context cannot exceed Low category
    guardrail_applied = False
    if matched_ids <= {"mild_urgency_keyword", "isolated_otp_mention"} and final_score > 20:
        final_score = 20
        guardrail_applied = True

    category = _select_category(final_score, config["categories"])
    recommended_actions = _build_recommended_actions(matched_ids, category["id"])

    return {
        "channel": normalized_channel,
        "char_count": len(cleaned_text),
        "score": final_score,
        "raw_score": raw_total,
        "score_breakdown": {
            "indicator_points": raw_indicator_score,
            "combination_points": combo_score,
            "benign_offset_points": benign_offset,
            "raw_total": raw_total,
            "final_score": final_score,
            "guardrail_applied": guardrail_applied,
        },
        "category": {
            "id": category["id"],
            "label": category["label"],
            "badge_kind": category["badge_kind"],
            "summary": category["summary"],
        },
        "matched_indicators": matched_rules,
        "matched_combinations": matched_combos,
        "benign_contexts": applied_benign,
        "recommended_actions": recommended_actions,
        "has_digital_arrest_signs": bool(
            matched_ids
            & {
                "arrest_threat",
                "legal_intimidation",
                "secrecy",
                "video_call_pressure",
                "safe_account",
            }
        ),
        "advisory_note": (
            "Advisory result only: this weighted rule score is not a calibrated probability "
            "and never proves a message is safe. Novel or code-mixed scam wording may not match."
        ),
        "rules_version": config["version"],
    }
