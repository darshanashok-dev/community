# Privacy and Security Architecture

## 1. Core Privacy Guarantees

### Message Analysis Privacy
- Pasted SMS, WhatsApp, and email text is processed **in memory only** inside `app/services/message_analyser.py`.
- Submitted messages are **never** written to SQLite, temporary files, cookies, sessions, or application logs.
- Submitted messages are **never** sent to any external API or third-party provider.
- Raw submitted text is not echoed back into the HTML form after submission.

### URL Analysis Privacy
- Submitted URLs are parsed **strictly as text** via `urllib.parse.urlsplit`.
- The backend **never** opens, fetches, connects to, or follows redirects on submitted URLs, and **never** expands shortened links (shorteners are labelled `"Destination not verified"`).
- Full submitted URLs are never stored in logs or databases.

### Opt-In External Reputation Checks
External lookups run **only** when the user explicitly checks the consent checkbox (`consent_external=True`):
1. **Privacy Reduction (`prepare_privacy_reduced_indicators`):**
   - Removes embedded username/password credentials (`userinfo`).
   - Removes the entire query string (`?k=v`) and URL fragment (`#...`).
   - Strips token-like, hex/UUID, email-like, and long numeric path segments.
   - Skips Safe Browsing lookup if the host is local/private, an unexpanded shortener, or cannot be safely reduced.
2. **Google Safe Browsing API v5:**
   - Sends only **4-byte SHA-256 hash prefixes** (base64-encoded) to `GET https://safebrowsing.googleapis.com/v5/hashes:search`.
   - Matches full 32-byte hashes locally in memory.
   - Attaches Google attribution and accuracy notices only to Safe Browsing results per Terms of Service.
3. **ICANN RDAP:**
   - Sends only the **registrable domain (`eTLD+1`)** to `https://rdap.org/domain/<domain>`.
   - Validates HTTPS scheme, port `443`, no userinfo, and non-private/non-loopback/non-reserved IP resolution before connecting.
4. **Unavailable Services:** Missing API keys, timeouts, rate limits, or network errors display `"Reputation information unavailable"` and are never treated as `"clean"`.

## 2. Application Security Controls

- **Debug Mode:** `DEBUG = False` by default in `config.py`.
- **Secrets Management:** `SECRET_KEY` and `SAFE_BROWSING_API_KEY` are loaded from environment variables (`.env`), never committed or exposed in frontend JS/HTML/logs.
- **Input Caps:** `MAX_CONTENT_LENGTH = 64 KB`, `MAX_MESSAGE_LENGTH = 5000`, `MAX_URL_LENGTH = 2048`.
- **Rate Limiting:** `InMemoryRateLimiter` limits `POST` requests per ephemeral-salted SHA-256 hash of `remote_addr` (`60 req/min` default).
- **SQL Injection Prevention:** `content_store.py` uses parameterized SQLite queries (`?`) exclusively across static tables.
- **XSS & Clickjacking Prevention:** Jinja2 auto-escaping (zero `|safe` filters), zero `innerHTML`/`eval` in JS, and strict security headers (`CSP default-src 'self'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `COOP: same-origin`, `CORP: same-origin`, `Cache-Control: no-store`).
- **Privacy-Aware Logging:** Logs only `req=<id> method=<METHOD> path=<PATH> status=<CODE> duration_ms=<MS>`. Query strings, request bodies, client IPs, and secrets are omitted.

## 3. Out-of-Scope & Non-Diagnostic Safeguards

- No APK upload, execution, or malware classification.
- No live call monitoring or WhatsApp client integration.
- Scores (`0–100`) are weighted rule indicators, not calibrated probabilities, and never certify safety.
