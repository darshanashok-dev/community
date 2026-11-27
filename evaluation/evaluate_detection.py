"""Detection evaluation script comparing the contextual rule engine vs. a keyword baseline.

Enforces strict dataset provenance and threshold checks:
- Default `--mode genuine-eval` blocks synthetic data and requires >=300 genuine messages
  (including >=100 genuine benign bank/UPI/delivery notifications) unless evaluating an
  already-validated held-out split (`--heldout-split` with verified genuine_eval provenance).
- `--mode synthetic-smoke` is strictly for development smoke verification and stamps the output
  clearly as `synthetic_smoke_only`.
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
from evaluation.dataset_validator import DatasetValidationError, validate_dataset_rows  # noqa: E402
from evaluation.split_dataset import compute_cohens_kappa  # noqa: E402

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

    # Benign class metrics for macro & class-imbalance-aware weighted F1
    neg_prec = tn / (tn + fn) if (tn + fn) > 0 else 0.0
    neg_rec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    neg_f1 = (2 * neg_prec * neg_rec / (neg_prec + neg_rec)) if (neg_prec + neg_rec) > 0 else 0.0

    pos_n = tp + fn
    neg_n = tn + fp
    total_n = pos_n + neg_n
    macro_f1 = (f1 + neg_f1) / 2.0
    weighted_f1 = ((f1 * pos_n) + (neg_f1 * neg_n)) / total_n if total_n > 0 else 0.0

    return {
        "class_counts": {"scam_positive": pos_n, "benign_negative": neg_n},
        "confusion_matrix": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
    }


def evaluate_csv(
    csv_path: Path,
    score_threshold: int = 31,
    rules_path: Path = DEFAULT_RULES_PATH,
    mode: str = "genuine-eval",
    heldout_split: bool = False,
) -> dict[str, Any]:
    """Validate dataset and evaluate contextual rule engine vs. keyword-only baseline."""
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    if heldout_split and mode == "genuine-eval":
        # Validate row-level schema, provenance=genuine_eval, annotations, and redaction
        summary = validate_dataset_rows(
            rows, fieldnames=fieldnames, mode="synthetic-smoke", allow_synthetic_only=True
        )
        if summary.synthetic_rows > 0:
            raise DatasetValidationError(
                "Held-out genuine evaluation blocked: synthetic_dev rows are present."
            )
    else:
        summary = validate_dataset_rows(rows, fieldnames=fieldnames, mode=mode)

    agreement = compute_cohens_kappa(rows)
    y_true: list[int] = []
    rule_preds: list[int] = []
    baseline_preds: list[int] = []
    rule_latencies_ms: list[float] = []
    baseline_latencies_ms: list[float] = []

    for row in rows:
        label_str = row["adjudicated_label"].strip().lower()
        text = row["redacted_text"]
        channel = row["channel"].strip().lower()
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

    eval_mode_label = (
        "synthetic_smoke_only"
        if mode == "synthetic-smoke"
        else ("genuine_heldout_split" if heldout_split else "genuine_full_eval")
    )

    return {
        "evaluation_mode": eval_mode_label,
        "dataset_path": str(csv_path),
        "total_samples": summary.total_rows,
        "benign_transactional_samples": summary.benign_transactional_rows,
        "dataset_origins": summary.origins,
        "inter_annotator_agreement": agreement,
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


def format_markdown_report(report: dict[str, Any]) -> str:
    re_m = report["contextual_rule_engine"]
    bl_m = report["keyword_only_baseline"]
    lines = [
        f"# Detection Evaluation Report (`{report['evaluation_mode']}`)",
        "",
        f"- **Dataset:** `{report['dataset_path']}` ({report['total_samples']} samples)",
        f"- **Dataset Origins:** `{report['dataset_origins']}`",
        f"- **Benign Bank/UPI/Delivery Samples:** {report['benign_transactional_samples']}",
        f"- **Score Threshold:** `>= {report['score_threshold']}`",
        f"- **Frozen Rules SHA-256:** `{report['rules_sha256']}`",
        f"- **Inter-Annotator Agreement:** `{report['inter_annotator_agreement']}`",
        "",
        "| Metric | Contextual Rule Engine | Keyword-Only Baseline |",
        "| :--- | ---: | ---: |",
        f"| Precision | {re_m['precision']} | {bl_m['precision']} |",
        f"| Recall | {re_m['recall']} | {bl_m['recall']} |",
        f"| F1-Score | {re_m['f1_score']} | {bl_m['f1_score']} |",
        f"| Macro-F1 | {re_m['macro_f1']} | {bl_m['macro_f1']} |",
        f"| Weighted-F1 | {re_m['weighted_f1']} | {bl_m['weighted_f1']} |",
        f"| False-Positive Rate (FPR) | {re_m['false_positive_rate']} | {bl_m['false_positive_rate']} |",
        f"| False-Negative Rate (FNR) | {re_m['false_negative_rate']} | {bl_m['false_negative_rate']} |",
        f"| Confusion Matrix (TP/FP/TN/FN) | {re_m['confusion_matrix']} | {bl_m['confusion_matrix']} |",
        f"| Avg Response (ms) | {re_m['avg_response_ms']} | {bl_m['avg_response_ms']} |",
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate message analyser vs. keyword-only baseline.")
    parser.add_argument("--input", required=True, type=Path, help="Path to labelled evaluation CSV.")
    parser.add_argument(
        "--mode",
        choices=["genuine-eval", "synthetic-smoke"],
        default="genuine-eval",
        help="Default genuine-eval blocks synthetic rows and requires >=300 genuine rows (>=100 benign transactional).",
    )
    parser.add_argument(
        "--heldout-split",
        action="store_true",
        help="Evaluate a ~30%% held-out genuine_eval test split produced by split_dataset.py.",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=31,
        help="Score threshold for positive warning/scam classification (default: 31).",
    )
    parser.add_argument("--output-json", type=Path, default=None, help="Optional path to save JSON report.")
    parser.add_argument("--output-md", type=Path, default=None, help="Optional path to save Markdown report.")
    args = parser.parse_args()

    try:
        report = evaluate_csv(
            args.input,
            score_threshold=args.threshold,
            mode=args.mode,
            heldout_split=args.heldout_split,
        )
    except DatasetValidationError as exc:
        print(f"EVALUATION BLOCKED:\n{exc}", file=sys.stderr)
        sys.exit(2)

    print(json.dumps(report, indent=2))
    if args.output_json:
        args.output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.output_md:
        args.output_md.write_text(format_markdown_report(report), encoding="utf-8")


if __name__ == "__main__":
    main()
