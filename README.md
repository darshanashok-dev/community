# Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications

A locally runnable, privacy-conscious Flask web application developed as an academic community project (RNS Institute of Technology, Dept. of CSE).

## Current Status: Phase 1 — Project Foundation and Frontend

Implemented in Phase 1:
- Modular Flask application factory (`app/`) and environment-based configuration (`config.py`)
- Security headers, `DEBUG=False` default, and privacy-aware request logging
- Accessible, responsive HTML5/CSS3/Vanilla JS frontend covering all planned pages:
  - Home (`/`)
  - Message Analyser (`/message-analyser`) — marked *Phase 2 Under Development*
  - URL Analyser (`/url-analyser`) — marked *Phase 3 Under Development*
  - Digital-Arrest Awareness (`/digital-arrest`)
  - After-Scam Assistance (`/after-scam`)
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
