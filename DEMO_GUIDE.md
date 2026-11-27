# Academic Demonstration Guide

Use this 10-step walkthrough for project evaluation using **fictional examples only**.

## Preparation Before Demo

```bash
source .venv/bin/activate
python run.py
```

Open `http://127.0.0.1:5000` in a browser (and optionally open Developer Tools -> Responsive Mode to show mobile layout).

---

## Step-by-Step Demonstration Script

1. **Home Page (`/`):**
   - Show the project overview, threat categories, privacy commitments (in-memory processing, no link visiting), advisory notice, and top navigation bar.
2. **Suspicious Phishing Message (`/message-analyser`):**
   - Select **SMS** or click **"Phishing KYC SMS"** (fictional example).
   - Submit and highlight: `0–100` score, *"Strong scam signs"* category, itemized rule contributions (impersonation + urgency + OTP/PAN request + link + phishing combination), and why an isolated `"OTP"` or `"Urgent"` benign alert stays in `0–30` (*"No known red flags"*).
3. **Digital-Arrest Scam Message (`/message-analyser`):**
   - Click **"Digital-Arrest Scam"** (fictional WhatsApp example) and submit.
   - Show the `combo_digital_arrest` explanation and contextual links directly to `/digital-arrest#call-checklist` and `/after-scam`.
4. **Suspicious URL (`/url-analyser`):**
   - Click **"Subdomain + Token URL"** (`http://sbi.co.in.kyc-verify.xyz/login/9f8e7d6c5b4a3210fedcba9876543210?otp=1234#top`) with the external consent box **unchecked**.
   - Show local structural findings (`brand_in_subdomain`, `risky_tld`, `suspicious_path_keywords`, `unusual_length`), registrable domain (`kyc-verify.xyz`), and confirm zero external requests were sent.
   - Also demonstrate **"Shortened URL"** (`https://bit.ly/example-short-code`) showing `"Destination not verified (shortened URL not expanded)"`.
5. **External Reputation Lookup with Explicit Consent (`/url-analyser`):**
   - Check the explicit consent checkbox and submit a URL (e.g. `https://cybercrime.gov.in/`).
   - Point out that credentials, queries, fragments, and token path segments are stripped, Safe Browsing v5 uses 4-byte SHA-256 prefixes (or gracefully shows `"Reputation information unavailable"` if `SAFE_BROWSING_API_KEY` is not set), and RDAP receives only the registrable domain (`cybercrime.gov.in`) as contextual metadata.
6. **Android Permission Guide (`/android-guide`):**
   - Review the four special-access permissions (*Accessibility*, *Notification access*, *Display over other apps*, *Install unknown apps*), Settings revocation paths, and the educational context helper (noting no APK scanning or malware classification is performed).
7. **Digital-Arrest Call Checklist (`/digital-arrest#call-checklist`):**
   - Tick warning signs (e.g., Authority Impersonation, Video-Call Pressure, Secrecy, Safe-Account Transfer) and submit to show the calm advisory assessment and disconnect instructions.
8. **After-Scam Assistance (`/after-scam`):**
   - Highlight `"You are not to blame."`, the 6 ordered recovery steps (`1930`, `cybercrime.gov.in`, contact bank, preserve transaction records, retain messages/evidence, official follow-up), and the session-only step progress checkboxes.
9. **Cybersecurity Lessons (`/learning`):**
   - Walk through one or two of the 6 fictional scenario-based lessons and show the official reporting links (`1930`, `cybercrime.gov.in`, `cert-in.org.in`).
10. **Interactive Quiz (`/learning#quiz`):**
    - Answer the 8 scenario questions (including one intentional wrong answer to demonstrate corrective explanation), submit to view the score and explanations, and show the **Retry Quiz** reset flow.
