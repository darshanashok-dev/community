# Testing and Evaluation Guide

## 1. Automated Application Test Suite

Run the full suite across all phases and improvement regressions:

```bash
source .venv/bin/activate
pytest -v
```

Test modules (`86` automated tests total):
- `tests/test_phase1_app.py`: App startup, all 7 pages, navigation, `/health`, 404, security headers, zero external CDNs, static assets.
- `tests/test_phase2_message_analyser.py`: Digital-arrest scams, KYC phishing, ambiguous medium risk, benign bank/UPI/delivery messages, isolated `"OTP"`/`"urgent"` guardrails, adversarial phrasing, validation, and no-log privacy.
- `tests/test_phase3_url_analyser.py`: IP/hex/octal hosts, subdomains, look-alikes, punycode, shorteners, privacy reduction, mocked Safe Browsing v5 protobuf/JSON responses, mocked RDAP, error/timeout/429 handling, and consent enforcement.
- `tests/test_phase4_awareness_and_after_scam.py`: Digital-arrest tactics, interactive call checklist levels, ordered after-scam steps (`1930`, `cybercrime.gov.in`, `"You are not to blame."`), and integration links.
- `tests/test_phase5_learning_and_android.py`: Static SQLite schema verification (no user-data tables), Android permission guide & context helper, 6 lessons, 8 quiz questions, score calculation, and retry flow.
- `tests/test_phase6_security_and_integration.py`: Extended security headers, XSS escaping, `429` rate limiting, `413`/`405` handlers, API key non-exposure, query-string log exclusion, RDAP SSRF guard, JS/template safety scans, and WCAG structural checks.
- `tests/test_phase7_end_to_end.py`: End-to-end 10-step flows, boundary inputs, and evaluation pipeline verification.
- `tests/test_improvements_qa.py`: Offline PSL extraction (`.com`, `.co.uk`, `.co.nz`, `.com.mx`, `.co.in`, IDN/punycode, IP/bare-suffix rejection), zero-width obfuscation & delivery OTP regressions, `score_breakdown` arithmetic, strict `genuine-eval` dataset gating, and UI polish checks.

## 2. Detection Evaluation Methodology (`evaluation/`)

1. **Dataset Preparation ([evaluation/DATASET_PROTOCOL.md](evaluation/DATASET_PROTOCOL.md)):**
   - Target: **300+ genuine, de-identified messages** (`dataset_origin = genuine_eval`) including **100+ genuine benign bank, UPI, and delivery messages**, with `source_provenance` and `license_or_permission`.
   - Annotate independently using two human annotators in [evaluation/annotation_template.csv](evaluation/annotation_template.csv), resolve disagreements in `adjudicated_label` + `disagreement_notes`, and group near-duplicate templates under `template_group_id`.
   - [evaluation/dataset_validator.py](evaluation/dataset_validator.py) blocks genuine evaluation if any `synthetic_dev` row is present, if `< 300` genuine rows or `< 100` benign transactional rows are present, if annotations are missing, or if unredacted PII patterns are detected.
2. **Template-Grouped 70/30 Split (`evaluation/split_dataset.py`):**
   ```bash
   python evaluation/split_dataset.py --input evaluation/your_labelled_300.csv --out-dir evaluation/splits --mode genuine-eval
   ```
   Computes Cohen's kappa and ensures neither `template_group_id` nor duplicate `redacted_text` crosses between `dev.csv` and `test.csv`.
3. **Frozen Evaluation & Keyword-Only Baseline Comparison (`evaluation/evaluate_detection.py`):**
   - Tune rule weights on `dev.csv` only, freeze `app/database/message_rules.json` (verified via SHA-256 digest), then evaluate once on `test.csv`:
   ```bash
   python evaluation/evaluate_detection.py --input evaluation/splits/test.csv --mode genuine-eval --heldout-split --threshold 31 --output-json evaluation/final_test_metrics.json --output-md evaluation/final_test_metrics.md
   ```
   - Outputs Precision, Recall, F1-score, Macro-F1, Weighted-F1, FPR (`FP/(FP+TN)`), FNR (`FN/(FN+TP)`), confusion matrix, class counts, avg/p95 response time, and side-by-side comparison with the naive keyword-only baseline.
   - **Honest status:** Only the 24-sample `synthetic_dev` smoke set ([evaluation/synthetic_smoke_samples.csv](evaluation/synthetic_smoke_samples.csv)) is included to verify pipeline correctness. Genuine 300+ field/public evaluation data has **not** been fabricated and remains **PENDING**.
   - **Latest Synthetic Smoke Pipeline Run (`--mode synthetic-smoke --threshold 31`, rules SHA-256 `a74d118faa722a13c2365d83808073a4f365b30883d79bd7499554be3d6e11b1`):**
     - Contextual rule engine (`24` `synthetic_dev` messages: `12` scam, `12` benign): `TP=12, FP=0, TN=12, FN=0`, `Precision=1.0`, `Recall=1.0`, `F1=1.0`, `Macro-F1=1.0`, `Weighted-F1=1.0`, `FPR=0.0`, `FNR=0.0`, `avg_response_ms=0.275`, `p95_response_ms=0.1489`.
     - Keyword-only baseline (`24` `synthetic_dev` messages): `TP=12, FP=9, TN=3, FN=0`, `Precision=0.5714`, `Recall=1.0`, `F1=0.7273`, `Macro-F1=0.5636`, `Weighted-F1=0.5636`, `FPR=0.75`, `FNR=0.0`.
     - Template-grouped 70/30 split (`--mode synthetic-smoke`): `Dev=16`, `Test=8`, zero overlap, Cohen's kappa `1.0`.
     - *Note:* These numbers verify script behaviour on synthetic development examples only; **genuine 300+ held-out evaluation remains PENDING**.

## 3. Voluntary Usability Evaluation (`evaluation/USABILITY_STUDY_PROTOCOL.md`)

- Prepared protocol for **20–30 voluntary participants** using informed consent, 5 fictional scenario tasks, anonymous participant codes (`P01`–`P30`), and [evaluation/usability_questionnaire_template.csv](evaluation/usability_questionnaire_template.csv).
- **Honest status:** Human participant sessions have not been conducted yet; no participant feedback has been fabricated.
