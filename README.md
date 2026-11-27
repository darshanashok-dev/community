# Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications

A locally runnable, privacy-conscious Flask web application developed as an academic community project (RNS Institute of Technology, Dept. of CSE).

## Current Status: Phase 6 — Security, Privacy & Complete Integration

Implemented through Phase 6:
- Modular Flask application factory (`app/`) with `DEBUG=False` default, security headers (`CSP`, `COOP`, `CORP`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`), privacy-aware logging, generic error handlers (`400`, `404`, `405`, `413`, `429`, `500`), and salted in-memory rate limiting
- All functional modules integrated end-to-end:
  - Home (`/`)
  - Message Analyser (`/message-analyser` and `POST /api/analyze-message`)
  - URL Analyser (`/url-analyser` and `POST /api/analyze-url`)
  - Digital-Arrest Awareness (`/digital-arrest` and `POST /api/digital-arrest-checklist`)
  - After-Scam Assistance (`/after-scam`)
  - Android Permission Guide (`/android-guide`)
  - Lessons & Official Reporting (`/learning` and `POST /api/quiz/submit`)
- Phase 6 audit documented in [SECURITY_AUDIT_PHASE6.md](SECURITY_AUDIT_PHASE6.md)

## Prerequisites

- Linux environment
- Python 3.10+ (tested on Python 3.14)

## Local Setup & Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Review `.env` and set a local `SECRET_KEY` (API keys such as `SAFE_BROWSING_API_KEY` are optional until Phase 3).

## Running Locally

```bash
source .venv/bin/activate
python run.py
```

Then open `http://127.0.0.1:5000` in your browser.

## Running Automated Tests

```bash
source .venv/bin/activate
pytest -v
```
