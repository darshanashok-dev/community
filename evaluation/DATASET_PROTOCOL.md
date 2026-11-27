# Dataset Collection, Redaction & Annotation Protocol

## 1. Target Dataset Composition

- **Target size:** At least **300 de-identified, independently labelled genuine messages** (`dataset_origin = genuine_eval`).
- **Benign representation:** At least **100 genuine benign banking, UPI, and delivery messages** (`source_type` in `bank_alert`, `upi_alert`, `delivery_alert`, `benign_bank`, `benign_upi`, `benign_delivery` with `adjudicated_label = benign`) alongside ordinary personal messages.
- **Explicit Provenance & Strict Separation:**
  - `synthetic_dev`: Fictional examples authored solely for development and smoke verification ([synthetic_smoke_samples.csv](synthetic_smoke_samples.csv)). **Blocked** from genuine held-out evaluation by [dataset_validator.py](dataset_validator.py).
  - `genuine_eval`: Real-world de-identified public/permissible scam examples and benign transactional notifications with `source_provenance` and `license_or_permission` documented for every row.
  - **Current status:** Only the 24-sample `synthetic_dev` smoke set is present in this repository. Genuine 300+ data has **not** been fabricated and remains pending external collection and two-annotator labelling.

## 2. De-Identification & Redaction Rules

Before entering any row into [annotation_template.csv](annotation_template.csv), replace all personal identifiers:
- Personal names -> `[NAME]`
- Phone numbers -> `[PHONE]`
- Real OTPs/PINs -> `[OTP]`
- Bank account numbers, card digits, UPI IDs, and UTR/transaction references -> `[ACCT]`, `[UPI_ID]`, `[REF]`
- Email addresses -> `[EMAIL]`
- Aadhaar/PAN identifiers -> `[ID]`

[dataset_validator.py](dataset_validator.py) automatically scans `redacted_text` and blocks evaluation if unredacted emails, Indian mobile numbers, 12-digit Aadhaar-like numbers, or PAN-like identifiers are detected.

## 3. Two-Annotator Labelling, Splitting & Frozen Evaluation

1. Assign a shared `template_group_id` to duplicate or near-duplicate campaign templates.
2. Two independent human annotators populate `annotator_1_label` and `annotator_2_label` (`scam` or `benign`).
3. Disagreements must be resolved in `adjudicated_label` with a mandatory explanation in `disagreement_notes`.
4. Split into ~70/30 `dev.csv` and `test.csv` (blocks `< 300` genuine rows, `< 100` benign transactional rows, synthetic leakage, template-group overlap, and exact duplicate text overlap):
   ```bash
   python evaluation/split_dataset.py --input evaluation/your_labelled_300.csv --out-dir evaluation/splits --mode genuine-eval
   ```
5. Tune rule weights in `app/database/message_rules.json` using `evaluation/splits/dev.csv` only, then freeze the rules and evaluate once on the held-out test set:
   ```bash
   python evaluation/evaluate_detection.py --input evaluation/splits/test.csv --mode genuine-eval --heldout-split --threshold 31 --output-json evaluation/final_test_metrics.json --output-md evaluation/final_test_metrics.md
   ```
6. To smoke-test the pipeline only on synthetic development data:
   ```bash
   python evaluation/evaluate_detection.py --input evaluation/synthetic_smoke_samples.csv --mode synthetic-smoke --threshold 31
   ```
