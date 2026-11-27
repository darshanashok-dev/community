# Cybersecurity Awareness Platform for Phishing, Digital Arrest Scams, and Malicious Applications

A locally runnable, privacy-conscious Flask web application developed as an academic community project (RNS Institute of Technology, Dept. of CSE).

## Current Status: Phase 5 — Android Permissions, Lessons & Interactive Quizzes

Implemented through Phase 5:
- Modular Flask application factory (`app/`) and environment-based configuration (`config.py`)
- Security headers, `DEBUG=False` default, and privacy-aware request logging
- Accessible, responsive HTML5/CSS3/Vanilla JS frontend covering all planned pages:
  - Home (`/`)
  - Message Analyser (`/message-analyser` and `POST /api/analyze-message`)
  - URL Analyser (`/url-analyser` and `POST /api/analyze-url`)
  - Digital-Arrest Awareness (`/digital-arrest` and `POST /api/digital-arrest-checklist`)
  - After-Scam Assistance (`/after-scam`)
  - Android Permission Guide (`/android-guide`) — detailed explanations of Accessibility, Notification access, Display over other apps, and Install unknown apps, plus context review helper (no APK scanning)
  - Lessons & Official Reporting (`/learning` and `POST /api/quiz/submit`) — 6 short scenario-based lessons, 8-question interactive quiz with explanations/scoring/retry, backed by static SQLite/JSON storage (`app/database/content.db`)

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
