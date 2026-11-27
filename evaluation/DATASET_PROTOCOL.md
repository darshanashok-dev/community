# Dataset Collection, Redaction & Annotation Protocol

## 1. Target Dataset Composition

- **Target size:** At least **300 de-identified, independently labelled messages**.
- **Benign representation:** At least **100 genuine benign banking, UPI, OTP, and delivery messages** alongside personal/ordinary messages to measure false-positive rate rigorously.
- **Distinction of data types:**
  - `synthetic_dev`: Fictional messages authored during Phase 2/Phase 7 development and smoke testing (such as [synthetic_smoke_samples.csv](synthetic_smoke_samples.csv)).
  - `genuine_eval`: Real-world de-identified public scam/advisory examples and benign transactional templates collected for formal evaluation.
  - **Current status:** Only the 24-sample `synthetic_dev` smoke set is included in this repository. The 300+ `genuine_eval` dataset has **not** been fabricated and must be populated from real de-identified sources before reporting final thesis metrics.

## 2. De-Identification & Redaction Checklist

Before recording any message in [annotation_template.csv](annotation_template.csv), remove or replace:
- Personal names -> `[NAME]`
- Phone numbers -> `[PHONE]`
- Real OTPs/PINs -> `[OTP]`
- Bank account numbers, card digits, UPI IDs, and UTR/transaction references -> `[ACCT]`, `[UPI_ID]`, `[REF]`
- Specific monetary amounts or dates where identifying -> `[AMOUNT]`, `[DATE]`

## 3. Two-Annotator Labelling & Template Grouping

1. Assign a `template_group_id` to cluster duplicate or near-duplicate campaign templates (e.g., identical KYC or bank alert wording with different numbers/links).
2. Two annotators independently populate `annotator_1_label` and `annotator_2_label` using `scam` or `benign`.
3. Disagreements are resolved through discussion/adjudication and recorded in `adjudicated_label` + `disagreement_notes`.
4. Run `python evaluation/split_dataset.py --input <labelled.csv> --out-dir evaluation/splits` to compute Cohen's kappa and perform a stratified **~70/30** dev/test split where **no `template_group_id` crosses the split**.
5. Tune rules using `dev.csv` only, record the SHA-256 hash of `app/database/message_rules.json` (freeze rules), and evaluate once on held-out `test.csv` via `evaluation/evaluate_detection.py`.
