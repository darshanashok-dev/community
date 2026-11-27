# Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications

A locally runnable, privacy-conscious Flask web application developed as an academic community project (RNS Institute of Technology, Dept. of CSE).

## Current Status: Phase 4 — Digital-Arrest Awareness & After-Scam Assistance

Implemented through Phase 4:
- Modular Flask application factory (`app/`) and environment-based configuration (`config.py`)
- Security headers, `DEBUG=False` default, and privacy-aware request logging
- Accessible, responsive HTML5/CSS3/Vanilla JS frontend covering all planned pages:
  - Home (`/`)
  - Message Analyser (`/message-analyser` and `POST /api/analyze-message`) — active in-memory contextual rule engine integrated with Digital-Arrest & After-Scam workflows
  - URL Analyser (`/url-analyser` and `POST /api/analyze-url`) — active text-only structural URL inspection + explicit opt-in privacy-reduced Google Safe Browsing v5 and registrable-domain RDAP lookups
  - Digital-Arrest Awareness (`/digital-arrest` and `POST /api/digital-arrest-checklist`) — complete coercion explanations and interactive stateless call checklist
  - After-Scam Assistance (`/after-scam`) — verified ordered recovery workflow (`1930`, `cybercrime.gov.in`, bank contact, evidence preservation) with calm, non-blaming guidance
  - Android Permission Guide (`/android-guide`)
  - Lessons & Official Reporting (`/learning`)

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
