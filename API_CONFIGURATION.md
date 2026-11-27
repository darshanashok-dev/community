# API Configuration Guide

## 1. Environment Variables

Copy `.env.example` to `.env` before running locally:

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `FLASK_ENV` | `production` | Runtime mode label |
| `FLASK_DEBUG` | `0` | Must remain `0` (`False`) during demonstrations and production |
| `FLASK_HOST` | `127.0.0.1` | Local bind interface |
| `FLASK_PORT` | `5000` | Local HTTP port |
| `SECRET_KEY` | Random 32-byte hex if unset | Flask session signing key |
| `SAFE_BROWSING_API_KEY` | Empty (optional) | Server-side Google Safe Browsing API v5 key |
| `EXTERNAL_API_TIMEOUT_SECONDS` | `5` | Timeout in seconds for Safe Browsing v5 and RDAP requests |
| `RDAP_BASE_URL` | `https://rdap.org/domain/` | HTTPS RDAP bootstrap endpoint |
| `MAX_MESSAGE_LENGTH` | `5000` | Maximum characters accepted by Message Analyser |
| `MAX_URL_LENGTH` | `2048` | Maximum characters accepted by URL Analyser |
| `RATE_LIMIT_ENABLED` | `1` | Enable in-memory POST rate limiting (`1` or `0`) |
| `RATE_LIMIT_REQUESTS_PER_MINUTE` | `60` | Maximum POST requests per minute per client bucket |

## 2. Google Safe Browsing API v5 Setup

- **Endpoint used:** `GET https://safebrowsing.googleapis.com/v5/hashes:search`
- **Protocol details:** Sends base64-encoded **4-byte SHA-256 hash prefixes** (`hashPrefixes` query params) derived from canonicalized, privacy-reduced URL expressions (up to 30 expressions). Parses native `application/x-protobuf` (`SearchHashesResponse`) or JSON responses and matches 32-byte full hashes locally.
- **How to obtain a key (non-commercial academic use):**
  1. Create or select a Google Cloud project for your non-commercial academic project.
  2. Enable the **Safe Browsing API** (`safebrowsing.googleapis.com`).
  3. Create an API key restricted to the Safe Browsing API and place it in `.env` as `SAFE_BROWSING_API_KEY=...`.
- **Terms of Service requirements:** Safe Browsing is free strictly for **non-commercial** use. Whenever Safe Browsing results are shown, Google attribution and reliability/accuracy notices are displayed; Google attribution is never attached to local heuristic warnings.
- **Behaviour without a key:** If `SAFE_BROWSING_API_KEY` is blank, local URL inspection still operates normally and Safe Browsing displays `"Reputation information unavailable"`.

## 3. RDAP Domain Lookup & Offline Public Suffix List Setup

- **Endpoint used:** `GET https://rdap.org/domain/<registrable_domain>` (requires no API key).
- **Registrable-domain extraction:** Uses `publicsuffix2==2.20191221` with an embedded offline Mozilla Public Suffix List snapshot (`PublicSuffixList(idna=True)`). No network call is made to determine suffixes, and bare public suffixes (such as `co.uk` or `com.mx`) return `None` rather than triggering an invalid RDAP query. To refresh the PSL snapshot during future maintenance, run `pip install --upgrade publicsuffix2` and re-pin in `requirements.txt`.
- **Privacy rule:** Only the registrable domain (`eTLD+1`, e.g., `example.co.in`, `example.co.uk`) is transmitted. Redirects to authoritative registry RDAP servers are validated for HTTPS port `443` and non-private IPs.
- **Database details:** The application uses `app/database/content.db` (SQLite) exclusively for static lessons, quizzes, and Android permission explanations—zero external API keys or user URLs are stored in SQLite.
