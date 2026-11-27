"""Detection evaluation script comparing the contextual rule engine vs. a keyword baseline.

Computes precision, recall, F1-score, false-positive rate (FPR), false-negative rate (FNR),
confusion matrix, class counts, response time, and verifies the frozen rules SHA-256 digest.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.services.message_analyser import DEFAULT_RULES_PATH, analyze_message  # noqa: E402

NAIVE_KEYWORDS_RE = re.compile(
    r"\b(?:otp|urgent|urgently|kyc|bank|upi|verify|blocked|suspended|arrest|warrant|cbi|police|parcel|click|link)\b",
    re.IGNORECASE,
)


def keyword_only_baseline(text: str) -> int:
    """Simple keyword-only baseline returning 1 if any naive keyword appears, else 0."""
    return 1 if NAIVE_KEYWORDS_RE.search(text or "") else 0


def rules_sha256(rules_path: Path = DEFAULT_RULES_PATH) -> str:
    return hashlib.sha256(rules_path.read_bytes()).hexdigest()


def compute_binary_metrics(y_true: list[int], y_pred: list[int]) -> dict[str, Any]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "class_counts": {"scam_positive": tp + fn, "benign_negative": tn + fp},
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def evaluate_csv(
    csv_path: Path,
    score_threshold: int = 31,
    rules_path: Path = DEFAULT_RULES_PATH,
) -> dict[str, Any]:
    """Run both the contextual rule engine and keyword-only baseline on a labelled CSV."""
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    if not rows:
        raise ValueError("Evaluation CSV contains no rows.")

    y_true: list[int] = []
    rule_preds: list[int] = []
    baseline_preds: list[int] = []
    rule_latencies_ms: list[float] = []
    baseline_latencies_ms: list[float] = []
    origins: dict[str, int] = {}

    for row in rows:
        label_str = (row.get("adjudicated_label") or "").strip().lower()
        if label_str not in {"scam", "benign"}:
            raise ValueError(f"Unsupported adjudicated_label '{label_str}' in row {row.get('sample_id')}")

        origin = (row.get("dataset_origin") or "unspecified").strip()
        origins[origin] = origins.get(origin, 0) + 1

        text = row.get("redacted_text") or ""
        channel = (row.get("channel") or "sms").strip().lower()
        y_true.append(1 if label_str == "scam" else 0)

        t0 = time.perf_counter()
        res = analyze_message(text, channel=channel, rules_path=rules_path)
        t1 = time.perf_counter()
        rule_latencies_ms.append((t1 - t0) * 1000.0)
        rule_preds.append(1 if res["score"] >= score_threshold else 0)

        b0 = time.perf_counter()
        b_pred = keyword_only_baseline(text)
        b1 = time.perf_counter()
        baseline_latencies_ms.append((b1 - b0) * 1000.0)
        baseline_preds.append(b_pred)

    rule_metrics = compute_binary_metrics(y_true, rule_preds)
    baseline_metrics = compute_binary_metrics(y_true, baseline_preds)

    rule_latencies_sorted = sorted(rule_latencies_ms)
    p95_idx = min(len(rule_latencies_sorted) - 1, int(0.95 * len(rule_latencies_sorted)))

    return {
        "dataset_path": str(csv_path),
        "total_samples": len(rows),
        "dataset_origins": origins,
        "score_threshold": score_threshold,
        "rules_sha256": rules_sha256(rules_path),
        "contextual_rule_engine": {
            **rule_metrics,
            "avg_response_ms": round(sum(rule_latencies_ms) / len(rule_latencies_ms), 4),
            "p95_response_ms": round(rule_latencies_sorted[p95_idx], 4),
        },
        "keyword_only_baseline": {
            **baseline_metrics,
            "avg_response_ms": round(sum(baseline_latencies_ms) / len(baseline_latencies_ms), 4),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate message analyser vs. keyword-only baseline.")
    parser.add_argument("--input", required=True, type=Path, help="Path to labelled evaluation CSV.")
    parser.add_argument(
        "--threshold",
        type=int,
        default=31,
        help="Score threshold for positive warning/scam classification (default: 31).",
    )
    parser.add_argument("--output-json", type=Path, default=None, help="Optional path to save JSON report.")
    args = parser.parse_args()

    report = evaluate_csv(args.input, score_threshold=args.threshold)
    print(json.dumps(report, indent=2))
    if args.output_json:
        args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
