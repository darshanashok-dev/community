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

---

## Likely Viva Questions & Implementation-Grounded Answers

1. **Why was rule-based detection selected instead of machine learning?**
   - Public awareness requires **explainability**: every warning returned by `app/services/message_analyser.py` lists the exact matched rule, why it matters, and its exact point contribution (`score_breakdown`). Rules require no large proprietary training corpus, execute in ~0.3 ms in memory, and can be audited line-by-line in `app/database/message_rules.json`.
2. **Why was machine learning not selected for the prototype?**
   - Training an ML/NLP classifier without at least thousands of representative regional/scam samples risks opaque black-box verdicts (`"scam 87%"`) without teaching users *why* a message is manipulative. ML is documented as a future extension once an ethically sourced corpus exists.
3. **How does the weighted scoring system work?**
   - Each of the 13 contextual rules contributes a configured positive weight (e.g., `safe_account` +30, `arrest_threat` +28, `otp_password_request` +24), combination rules (`combo_digital_arrest`, `combo_credential_phishing`, `combo_unofficial_channel_coercion`) add synergy points when high-risk cues co-occur, and benign-context rules subtract small offsets when no coercive signals exist. The sum is bounded to `0–100` (`0–30` *No known red flags*, `31–65` *Some warning signs*, `66–100` *Strong scam signs*) and explicitly presented as an advisory indicator, never a probability.
4. **How are false positives reduced on genuine banking, UPI, and delivery messages?**
   - Negative lookbehinds (`(?<!do not )(?<!don't )(?<!never )`) prevent `"Do not share this OTP with anyone"` from triggering `otp_password_request`; doorstep delivery phrasing (`Share OTP ... with delivery agent only when receiving parcel`) is excluded from `otp_password_request`; isolated `"OTP"` (`+5`) and `"urgent"` (`+8`) rules are capped at `<= 20` by the isolated-keyword guardrail; and `benign_protective_otp`, `benign_bank_upi_receipt`, and `benign_delivery_update` offsets offset benign alerts when coercive/impersonation cues are absent.
5. **How are URLs analysed without visiting them?**
   - `app/services/url_analyser.py` parses the URL string strictly as text with `urllib.parse.urlsplit`, `ipaddress`, and offline `publicsuffix2` (Mozilla PSL). It never opens sockets, follows redirects, fetches HTML, or expands shortened URLs (`bit.ly` etc. are marked `"Destination not verified"`).
6. **What is URL canonicalisation and why is a Public Suffix List used?**
   - Before hashing for Safe Browsing, `url_analyser.py` strips userinfo/query/fragment/token segments, lowercases and strips trailing dots from the host, normalizes IPv4/IPv6 forms, resolves `/./` and `/../`, and collapses `//` so attackers cannot evade threat lists via encoding variations. Offline `publicsuffix2` computes exact `eTLD+1` across multipart suffixes (`.co.uk`, `.co.nz`, `.com.mx`, `.co.in`) and IDNs without making network requests or treating bare suffixes (`co.uk`) as registrable domains.
7. **How does Google Safe Browsing v5 work in this project?**
   - Only when the user checks `consent_external`, `prepare_privacy_reduced_indicators` strips credentials, query strings, fragments, and token-like path segments, canonicalizes the reduced URL, generates up to 30 host-suffix/path-prefix expressions, hashes them with SHA-256, and sends **only 4-byte base64 hash prefixes** via `GET https://safebrowsing.googleapis.com/v5/hashes:search`. Full 32-byte hashes from the protobuf/JSON response are matched locally, and missing keys/errors display `"Reputation information unavailable"`.
8. **Why is RDAP used, and what privacy reduction applies?**
   - RDAP (`https://rdap.org/domain/<registrable_domain>`) retrieves contextual domain registration metadata (registrar, registration date, age, status) to help users spot newly registered domains without implying age proves malice or safety. Only the registrable domain (`eTLD+1` extracted offline via `publicsuffix2`) is sent, over SSRF-validated HTTPS port `443`.
9. **How does transient processing preserve privacy compared to static storage?**
   - Submitted messages and full URLs stay in request memory only and are discarded immediately after rendering; they are never written to SQLite (`content.db` holds static lessons, quizzes, and permissions only), never written to logs (`app/__init__.py` logs only request ID, method, `request.path`, status, and timing), and never echoed back into form HTML.
10. **Why can permissions alone not establish that an Android app is malware?**
    - Sensitive permissions (Accessibility, Notification access, Display over apps, Install unknown apps) have genuine legitimate uses such as screen readers, smartwatch companions, and chat bubbles. Context—such as whether an APK was sideloaded via chat—matters, so `/android-guide` strictly provides educational guidance and never classifies apps or scans APKs.
11. **How are precision, recall, F1, and false-positive rate calculated, and how is dataset leakage prevented?**
    - `evaluation/evaluate_detection.py` computes `Precision = TP/(TP+FP)`, `Recall = TP/(TP+FN)`, `F1`, `Macro-F1`, `Weighted-F1`, `FPR = FP/(FP+TN)`, and `FNR = FN/(FN+TP)` alongside a keyword-only baseline. `evaluation/split_dataset.py` groups duplicate/near-duplicate templates under `template_group_id`, checks token-Jaccard near-duplicate crossings (`>= 0.85`), and prevents any group from crossing between `dev.csv` and `test.csv`.
12. **How is inter-annotator agreement measured with Cohen's kappa?**
    - `compute_cohens_kappa` in `evaluation/split_dataset.py` reports `annotated_count`, `agreement_count`, `disagreement_count`, `missing_annotation_count`, `raw_agreement`, and Cohen's $\kappa = (p_o - p_e)/(1 - p_e)$ comparing two independent human annotators before adjudication.
13. **What are the actual documented limitations?**
    - English-only prototype (Hindi/Kannada/code-mixed future work); advisory rules can miss novel scams (`"No known red flags"` never proves safety); shortened URLs remain unverified; live Safe Browsing requires a user API key and network access; and genuine 300+ dataset evaluation plus the 20–30 participant usability study remain pending human collection/execution.

