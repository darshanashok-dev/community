"""Phase 6 tests: security controls, privacy guarantees, XSS escaping, rate limiting, and full integration."""

import logging
import re
from pathlib import Path

import pytest

from app import create_app
from app.services.reputation_client import _is_public_https_rdap_url
from config import Config, TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def test_extended_security_headers_and_cookie_defaults(client):
    res = client.get("/")
    assert res.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert res.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert res.headers["X-Content-Type-Options"] == "nosniff"
    assert res.headers["X-Frame-Options"] == "DENY"
    assert res.headers["Referrer-Policy"] == "no-referrer"
    assert Config.SESSION_COOKIE_HTTPONLY is True
    assert Config.SESSION_COOKIE_SAMESITE == "Lax"


def test_xss_payload_escaped_and_not_echoed_unsafely(client):
    xss_payload = "<script>alert('xss')</script>"
    res_msg = client.post(
        "/message-analyser",
        data={"channel": "sms", "message": f"Urgent KYC notice {xss_payload}"},
    )
    assert res_msg.status_code == 200
    html_msg = res_msg.get_data(as_text=True)
    assert xss_payload not in html_msg

    res_url = client.post(
        "/url-analyser",
        data={"url": f"https://example.com/{xss_payload}"},
    )
    html_url = res_url.get_data(as_text=True)
    assert "<script>alert" not in html_url


def test_rate_limiting_enforced_when_enabled():
    class LimitedConfig(TestingConfig):
        RATE_LIMIT_ENABLED = True
        RATE_LIMIT_REQUESTS_PER_MINUTE = 3

    app = create_app(LimitedConfig)
    c = app.test_client()

    for _ in range(3):
        r = c.post("/api/analyze-message", json={"channel": "sms", "message": "Hello"})
        assert r.status_code == 200

    blocked = c.post("/api/analyze-message", json={"channel": "sms", "message": "Hello"})
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert "Too many submissions" in blocked.get_json()["error"]


def test_payload_too_large_and_method_not_allowed_handlers(client):
    res_405 = client.get("/api/analyze-message")
    assert res_405.status_code == 405
    assert "error" in res_405.get_json()

    oversized_body = '{"channel": "sms", "message": "' + ("a" * 70000) + '"}'
    res_413 = client.post(
        "/api/analyze-message",
        data=oversized_body,
        content_type="application/json",
    )
    assert res_413.status_code == 413
    assert "exceeds the maximum allowed request size" in res_413.get_json()["error"]


def test_api_key_never_exposed_in_responses_or_logs(caplog):
    class SecretKeyConfig(TestingConfig):
        SAFE_BROWSING_API_KEY = "SUPER_SECRET_SB_KEY_XYZ987"

    app = create_app(SecretKeyConfig)
    c = app.test_client()

    with caplog.at_level(logging.INFO):
        for path in [
            "/",
            "/message-analyser",
            "/url-analyser",
            "/digital-arrest",
            "/after-scam",
            "/android-guide",
            "/learning",
            "/static/js/url_analyser.js",
        ]:
            resp = c.get(path)
            assert resp.status_code == 200
            assert "SUPER_SECRET_SB_KEY_XYZ987" not in resp.get_data(as_text=True)

    assert "SUPER_SECRET_SB_KEY_XYZ987" not in caplog.text


def test_query_strings_not_logged(client, caplog):
    with caplog.at_level(logging.INFO):
        res = client.get("/?secret_query=DO_NOT_LOG_THIS_TOKEN")
    assert res.status_code == 200
    assert "DO_NOT_LOG_THIS_TOKEN" not in caplog.text


def test_rdap_ssrf_guard_blocks_private_and_non_443_targets():
    assert _is_public_https_rdap_url("http://rdap.org/domain/example.com") is False
    assert _is_public_https_rdap_url("https://127.0.0.1/domain/example.com") is False
    assert _is_public_https_rdap_url("https://169.254.169.254/latest") is False
    assert _is_public_https_rdap_url("https://10.0.0.1/domain/example.com") is False
    assert _is_public_https_rdap_url("https://localhost/domain/example.com") is False
    assert _is_public_https_rdap_url("https://rdap.org:8443/domain/example.com") is False
    assert _is_public_https_rdap_url("https://user@rdap.org/domain/example.com") is False


def test_frontend_static_js_and_templates_free_of_unsafe_dom_patterns():
    project_root = Path(__file__).resolve().parent.parent
    for js_file in (project_root / "app" / "static" / "js").glob("*.js"):
        content = js_file.read_text(encoding="utf-8")
        assert "innerHTML" not in content
        assert "outerHTML" not in content
        assert "document.write" not in content
        assert not re.search(r"\beval\s*\(", content)

    for html_file in (project_root / "app" / "templates").rglob("*.html"):
        content = html_file.read_text(encoding="utf-8")
        assert "| safe" not in content
        assert "|safe" not in content


def test_end_to_end_accessibility_and_module_integration(client):
    # Verify all pages include skip link, single h1, and main landmark
    pages = [
        "/",
        "/message-analyser",
        "/url-analyser",
        "/digital-arrest",
        "/after-scam",
        "/android-guide",
        "/learning",
    ]
    for path in pages:
        html = client.get(path).get_data(as_text=True)
        assert 'class="skip-link"' in html
        assert '<main id="main-content"' in html
        assert html.count("<h1") == 1

    # Verify distinct aria-labels on after-scam checkboxes
    after_html = client.get("/after-scam").get_data(as_text=True)
    for step_num in range(1, 7):
        assert f"Mark step {step_num} complete:" in after_html
