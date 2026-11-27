"""Source/template-grouped ~70/30 stratified dataset splitter & annotator agreement tool.

Ensures duplicate or near-duplicate message templates (sharing `template_group_id`)
never cross the boundary between the development and held-out test sets.
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import defaultdict
from pathlib import Path
from typing import Any


def compute_cohens_kappa(rows: list[dict[str, str]]) -> dict[str, Any]:
    """Compute raw agreement and Cohen's kappa between annotator_1_label and annotator_2_label."""
    valid = [
        (r.get("annotator_1_label", "").strip().lower(), r.get("annotator_2_label", "").strip().lower())
        for r in rows
        if r.get("annotator_1_label", "").strip() and r.get("annotator_2_label", "").strip()
    ]
    n = len(valid)
    if n == 0:
        return {"annotated_count": 0, "raw_agreement": None, "cohens_kappa": None}

    agree = sum(1 for a, b in valid if a == b)
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
        "raw_agreement": round(p_o, 4),
        "cohens_kappa": round(kappa, 4),
    }


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

        # Ensure at least one group stays in test when >= 2 groups exist
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Group-aware 70/30 stratified dataset splitter.")
    parser.add_argument("--input", required=True, type=Path, help="Input labelled CSV path.")
    parser.add_argument("--out-dir", required=True, type=Path, help="Output directory for dev.csv and test.csv.")
    parser.add_argument("--dev-ratio", type=float, default=0.70, help="Target dev fraction (default 0.70).")
    parser.add_argument("--seed", type=int, default=42, help="Deterministic shuffle seed.")
    args = parser.parse_args()

    with args.input.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        fieldnames = reader.fieldnames or []
        rows = list(reader)

    agreement = compute_cohens_kappa(rows)
    dev_rows, test_rows = group_stratified_split(rows, dev_ratio=args.dev_ratio, seed=args.seed)

    # Verify zero template-group leakage
    dev_groups = {r["template_group_id"] for r in dev_rows if r.get("template_group_id")}
    test_groups = {r["template_group_id"] for r in test_rows if r.get("template_group_id")}
    overlap = dev_groups & test_groups
    if overlap:
        raise RuntimeError(f"Template group leakage detected: {sorted(overlap)}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for name, subset in [("dev.csv", dev_rows), ("test.csv", test_rows)]:
        out_path = args.out_dir / name
        with out_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(subset)

    print(f"Total rows: {len(rows)} | Dev: {len(dev_rows)} | Test: {len(test_rows)}")
    print(f"Inter-annotator agreement: {agreement}")


if __name__ == "__main__":
    main()
