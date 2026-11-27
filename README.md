# Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications

A locally runnable, privacy-conscious Flask web application built as an academic community project (Department of Computer Science & Engineering, RNS Institute of Technology, Bengaluru).

## Project Overview

The platform helps the general public:
- Identify contextual phishing and digital-arrest indicators in SMS, WhatsApp, and email messages (`0–100` explainable weighted score).
- Inspect suspicious HTTP/HTTPS URLs strictly as text—without ever visiting, opening, or following redirects—with optional explicit opt-in Google Safe Browsing API v5 (4-byte SHA-256 hash-prefix) and registrable-domain RDAP lookups.
- Recognise digital-arrest coercion tactics via an interactive call checklist.
- Follow calm, ordered after-scam recovery steps (`1930`, `cybercrime.gov.in`, bank contact, evidence preservation).
- Understand sensitive Android special-access permissions (educational guidance only; no APK scanning or malware classification).
- Practice with 6 short scenario-based lessons, an 8-question interactive quiz, and verified official reporting links.

> **Advisory Disclaimer:** All scores and indicators are educational aids—not calibrated probabilities—and never prove that any message, URL, caller, or application is safe.

## Technology Stack

- **Frontend:** HTML5, CSS3, Vanilla JavaScript (no external CDNs or UI frameworks)
- **Backend:** Python 3.10+, Flask 3.1.3
- **Static Storage:** SQLite (`app/database/content.db`) and JSON (`app/database/*.json`) for rules, lessons, permissions, and quiz questions only
- **External Integrations (Opt-In Only):** Google Safe Browsing API v5 (`hashes:search`), ICANN RDAP (`rdap.org`)

## Folder Structure

```text
project/
├── app/
│   ├── __init__.py
│   ├── database/
│   │   ├── __init__.py
│   │   ├── android_permissions.json
│   │   ├── content_store.py
│   │   ├── digital_arrest_checklist.json
│   │   ├── learning_content.json
│   │   ├── message_rules.json
│   │   └── url_rules.json
│   ├── routes/
│   │   ├── __init__.py
│   │   ├── analyzer.py
│   │   └── main.py
│   ├── services/
│   │   ├── __init__.py
│   │   ├── digital_arrest_service.py
│   │   ├── learning_service.py
│   │   ├── message_analyser.py
│   │   ├── rate_limiter.py
│   │   ├── reputation_client.py
│   │   └── url_analyser.py
│   ├── static/
│   │   ├── css/styles.css
│   │   ├── images/shield.svg
│   │   └── js/
│   └── templates/
│       ├── base.html
│       ├── components.html
│       ├── errors/
│       └── *.html
├── evaluation/
│   ├── DATASET_PROTOCOL.md
│   ├── USABILITY_STUDY_PROTOCOL.md
│   ├── annotation_template.csv
│   ├── evaluate_detection.py
│   ├── split_dataset.py
│   ├── synthetic_smoke_samples.csv
│   └── usability_questionnaire_template.csv
├── references/
├── tests/
├── config.py
├── requirements.txt
├── .env.example
├── run.py
├── PROJECT_ARCHITECTURE.md
├── PRIVACY_AND_SECURITY.md
├── TESTING_AND_EVALUATION.md
├── API_CONFIGURATION.md
├── DEMO_GUIDE.md
└── SECURITY_AUDIT_PHASE6.md
```

## Local Installation & Execution (Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` to set a random `SECRET_KEY` and (optionally) `SAFE_BROWSING_API_KEY`. Then run locally:

```bash
source .venv/bin/activate
python run.py
```

Open `http://127.0.0.1:5000` in your browser. Do not deploy publicly without TLS/HTTPS reverse-proxy termination.

## Testing & Evaluation Commands

```bash
source .venv/bin/activate
pip check
pytest -v
python evaluation/evaluate_detection.py --input evaluation/synthetic_smoke_samples.csv
```

## Documentation Index

- [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) — System design, data flow, and Mermaid architecture diagram
- [PRIVACY_AND_SECURITY.md](PRIVACY_AND_SECURITY.md) — Transient processing, privacy reduction, security headers, and logging rules
- [API_CONFIGURATION.md](API_CONFIGURATION.md) — Environment variables, Google Safe Browsing v5, and RDAP setup
- [TESTING_AND_EVALUATION.md](TESTING_AND_EVALUATION.md) — Automated tests, dataset evaluation protocol, and usability study plan
- [DEMO_GUIDE.md](DEMO_GUIDE.md) — 10-step academic demonstration script with fictional inputs
- [SECURITY_AUDIT_PHASE6.md](SECURITY_AUDIT_PHASE6.md) — Phase 6 security, dependency, and accessibility review
- [FINAL_PROJECT_REPORT.md](FINAL_PROJECT_REPORT.md) — Final academic project report (23 sections + Mermaid diagrams + honest evaluation status)
- [community_project_ppt_updated.pptx](community_project_ppt_updated.pptx) — Updated 22-slide final review & viva presentation

## Known Limitations

- English is the only supported language; Hindi, Kannada, and code-mixed scam wording may not match rules.
- Novel phishing wording can score `0–30`; `"No known red flags"` never proves safety.
- Shortened URLs are never expanded and remain labelled `"Destination not verified"`.
- Google Safe Browsing v5 requires a non-commercial API key and external network access; missing/unavailable services are always shown as `"Reputation information unavailable"`.
- Formal evaluation on 300+ genuine de-identified messages and a 20–30 participant user study are prepared as templates/scripts and have not yet been executed on external field data.
