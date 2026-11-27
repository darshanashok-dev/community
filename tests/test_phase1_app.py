"""Phase 1 tests: application startup, routes, navigation, security headers, and privacy defaults."""

import pytest

from app import create_app
from config import Config, TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


@pytest.mark.parametrize(
    "path, expected_text",
    [
        ("/", "Public Cybersecurity Awareness"),
        ("/message-analyser", "Phishing &amp; Digital-Arrest Message Analyser"),
        ("/url-analyser", "Text-Only URL Analyser"),
        ("/digital-arrest", "Recognising Digital-Arrest Scams"),
        ("/after-scam", "You are not to blame."),
        ("/android-guide", "Android Special-Access Permission Guide"),
        ("/learning", "Cybersecurity Lessons, Quizzes &amp; Official Reporting"),
    ],
)
def test_all_phase1_pages_load_successfully(client, path, expected_text):
    response = client.get(path)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert expected_text in html
    # Navigation links should exist on every page
    assert 'href="/message-analyser"' in html
    assert 'href="/url-analyser"' in html
    assert 'href="/digital-arrest"' in html
    assert 'href="/after-scam"' in html
    assert 'href="/android-guide"' in html
    assert 'href="/learning"' in html


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok", "phase": 6}


def test_404_error_page(client):
    response = client.get("/non-existent-route")
    assert response.status_code == 404
    assert "Page Not Found (404)" in response.get_data(as_text=True)


def test_security_headers_present(client):
    response = client.get("/")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["Cache-Control"] == "no-store"


def test_no_external_cdn_assets_in_html(client):
    response = client.get("/")
    html = response.get_data(as_text=True)
    assert "https://" not in html
    assert "http://" not in html


def test_debug_mode_disabled_by_default():
    assert Config.DEBUG is False
    app = create_app(Config)
    assert app.debug is False


@pytest.mark.parametrize(
    "asset_path",
    [
        "/static/css/styles.css",
        "/static/js/main.js",
        "/static/images/shield.svg",
    ],
)
def test_static_assets_served(client, asset_path):
    response = client.get(asset_path)
    assert response.status_code == 200

