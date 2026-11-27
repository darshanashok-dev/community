"""Source/template-grouped ~70/30 stratified dataset splitter & annotator agreement tool.

Ensures duplicate or near-duplicate message templates (sharing `template_group_id`
or identical normalized text) never cross between dev and held-out test sets.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.dataset_validator import DatasetValidationError, validate_dataset_rows  # noqa: E402


def compute_cohens_kappa(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compute raw agreement, disagreement, missing counts, and Cohen's kappa."""
    valid: list[tuple[str, str]] = []
    missing_count = 0
    for r in rows:
        a1 = (r.get("annotator_1_label") or "").strip().lower()
        a2 = (r.get("annotator_2_label") or "").strip().lower()
        if a1 and a2:
            valid.append((a1, a2))
        else:
            missing_count += 1

    n = len(valid)
    if n == 0:
        return {
            "annotated_count": 0,
            "agreement_count": 0,
            "disagreement_count": 0,
            "missing_annotation_count": missing_count,
            "raw_agreement": None,
            "cohens_kappa": None,
        }

    agree = sum(1 for a, b in valid if a == b)
    disagree = n - agree
    p_o = agree / n

    labels = sorted({a for a, _ in valid} | {b for _, b in valid})
    p_e = 0.0
    for lbl in labels:
        p1 = sum(1 for a, _ in valid if a == lbl) / n
        p2 = sum(1 for _, b in valid if b == lbl) / n
        p_e += p1 * p2

    kappa = 1.0 if p_e == 1.0 else (p_o - p_e) / (1.0 - p_e)
    return {
        "annotated_count": n,
        "agreement_count": agree,
        "disagreement_count": disagree,
        "missing_annotation_count": missing_count,
        "raw_agreement": round(p_o, 4),
        "cohens_kappa": round(kappa, 4),
    }


def _norm_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").strip().lower())


def _token_set(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]+", (text or "").lower()))


def find_near_duplicate_crossings(
    dev_rows: list[dict[str, str]],
    test_rows: list[dict[str, str]],
    threshold: float = 0.85,
) -> list[tuple[str, str, float]]:
    """Detect near-duplicate message pairs across dev/test splits via token Jaccard."""
    dev_tokens = [
        ((r.get("sample_id") or "?").strip(), _token_set(r.get("redacted_text", "")))
        for r in dev_rows
    ]
    test_tokens = [
        ((r.get("sample_id") or "?").strip(), _token_set(r.get("redacted_text", "")))
        for r in test_rows
    ]
    crossings: list[tuple[str, str, float]] = []
    for d_id, d_tok in dev_tokens:
        if len(d_tok) < 4:
            continue
        for t_id, t_tok in test_tokens:
            if len(t_tok) < 4:
                continue
            union = d_tok | t_tok
            sim = len(d_tok & t_tok) / len(union) if union else 0.0
            if sim >= threshold:
                crossings.append((d_id, t_id, round(sim, 3)))
    return crossings


def group_stratified_split(
    rows: list[dict[str, str]],
    dev_ratio: float = 0.70,
    seed: int = 42,
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Split rows into (dev_rows, test_rows) keeping each template_group_id intact."""
    groups_by_label: dict[str, dict[str, list[dict[str, str]]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for row in rows:
        label = (row.get("adjudicated_label") or "").strip().lower()
        group_id = (row.get("template_group_id") or row.get("sample_id") or "").strip()
        groups_by_label[label][group_id].append(row)

    rng = random.Random(seed)
    dev_rows: list[dict[str, str]] = []
    test_rows: list[dict[str, str]] = []

    for label in sorted(groups_by_label.keys()):
        group_items = list(groups_by_label[label].items())
        rng.shuffle(group_items)

        total_in_class = sum(len(members) for _, members in group_items)
        target_dev = round(total_in_class * dev_ratio)

        current_dev = 0
        for idx, (_gid, members) in enumerate(group_items):
            remaining_groups = len(group_items) - idx
            if len(group_items) >= 2 and remaining_groups == 1 and current_dev > 0 and not any(
                (m.get("adjudicated_label") or "").strip().lower() == label for m in test_rows
            ):
                test_rows.extend(members)
                continue

            if current_dev < target_dev:
                dev_rows.extend(members)
                current_dev += len(members)
            else:
                test_rows.extend(members)

    return dev_rows, test_rows


def split_and_validate(
    input_path: Path,
    out_dir: Path,
    mode: str = "genuine-eval",
    dev_ratio: float = 0.70,
    seed: int = 42,
) -> dict[str, Any]:
    """Validate dataset, perform group-stratified split, and write dev.csv & test.csv."""
    with input_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)

    summary = validate_dataset_rows(rows, fieldnames=fieldnames, mode=mode)
    agreement = compute_cohens_kappa(rows)
    dev_rows, test_rows = group_stratified_split(rows, dev_ratio=dev_ratio, seed=seed)

    # Verify zero template-group or exact-text leakage
    dev_groups = {r["template_group_id"].strip() for r in dev_rows}
    test_groups = {r["template_group_id"].strip() for r in test_rows}
    if dev_groups & test_groups:
        raise DatasetValidationError(
            f"Template group leakage detected: {sorted(dev_groups & test_groups)}"
        )

    dev_texts = {_norm_text(r["redacted_text"]) for r in dev_rows}
    test_texts = {_norm_text(r["redacted_text"]) for r in test_rows}
    if dev_texts & test_texts:
        raise DatasetValidationError(
            "Duplicate redacted_text crossed the dev/test boundary. Assign shared template_group_id values."
        )

    near_dups = find_near_duplicate_crossings(dev_rows, test_rows, threshold=0.85)
    if near_dups:
        sample_pair = near_dups[0]
        raise DatasetValidationError(
            f"Near-duplicate template leakage detected across dev/test splits "
            f"(e.g., {sample_pair[0]} vs {sample_pair[1]}, similarity={sample_pair[2]}). "
            "Group related templates under the same template_group_id."
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, subset in [("dev.csv", dev_rows), ("test.csv", test_rows)]:
        out_path = out_dir / name
        with out_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(subset)

    return {
        "mode": summary.mode,
        "total_rows": summary.total_rows,
        "dev_rows": len(dev_rows),
        "test_rows": len(test_rows),
        "class_counts": summary.class_counts,
        "inter_annotator_agreement": agreement,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Group-aware 70/30 stratified dataset splitter.")
    parser.add_argument("--input", required=True, type=Path, help="Input labelled CSV path.")
    parser.add_argument("--out-dir", required=True, type=Path, help="Output directory for dev.csv and test.csv.")
    parser.add_argument(
        "--mode",
        choices=["genuine-eval", "synthetic-smoke"],
        default="genuine-eval",
        help="Validation mode: genuine-eval enforces 300+ genuine messages; synthetic-smoke allows synthetic_dev only.",
    )
    parser.add_argument("--dev-ratio", type=float, default=0.70, help="Target dev fraction (default 0.70).")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic shuffle seed.")
    args = parser.parse_args()

    try:
        result = split_and_validate(
            input_path=args.input,
            out_dir=args.out_dir,
            mode=args.mode,
            dev_ratio=args.dev_ratio,
            seed=args.seed,
        )
    except DatasetValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    print(
        f"Mode: {result['mode']} | Total: {result['total_rows']} "
        f"| Dev: {result['dev_rows']} | Test: {result['test_rows']}"
    )
    print(f"Class counts: {result['class_counts']}")
    print(f"Inter-annotator agreement: {result['inter_annotator_agreement']}")


if __name__ == "__main__":
    main()
