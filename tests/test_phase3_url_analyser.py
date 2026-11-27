"""Phase 3 tests: local URL parsing, privacy reduction, Safe Browsing v5, RDAP, consent, and error handling."""

import base64
import hashlib
import logging

import pytest
import requests

from app import create_app
from app.services.reputation_client import (
    SAFE_BROWSING_V5_ENDPOINT,
    check_safe_browsing_v5,
    decode_search_hashes_response,
    lookup_rdap_domain,
)
from app.services.url_analyser import (
    UrlValidationError,
    analyze_url_locally,
    prepare_privacy_reduced_indicators,
)
from config import TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def _encode_varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


def _pb_bytes(field_num: int, data: bytes) -> bytes:
    return _encode_varint((field_num << 3) | 2) + _encode_varint(len(data)) + data


def _pb_varint(field_num: int, value: int) -> bytes:
    return _encode_varint((field_num << 3) | 0) + _encode_varint(value)


class _DummyResponse:
    def __init__(self, status_code=200, content=b"", json_data=None, headers=None):
        self.status_code = status_code
        self.content = content
        self._json = json_data
        self.headers = headers or {}

    def json(self):
        if self._json is None:
            raise ValueError("No JSON")
        return self._json


def test_local_ip_host_and_apk_url_detected():
    res = analyze_url_locally("http://0x7f.0.0.1:8080/update/bank-app.apk")
    ids = {i["id"] for i in res["matched_indicators"]}
    assert "ip_host" in ids
    assert "apk_download_hint" in ids
    assert "non_standard_port" in ids
    assert res["score"] >= 66
    assert res["category"]["label"] == "Strong scam signs"


def test_local_brand_in_subdomain_and_risky_tld():
    res = analyze_url_locally("https://sbi.co.in.kyc-verify.xyz/login/session")
    ids = {i["id"] for i in res["matched_indicators"]}
    assert "brand_in_subdomain" in ids
    assert "risky_tld" in ids
    assert "suspicious_path_keywords" in ids
    assert res["registrable_domain"] == "kyc-verify.xyz"
    assert res["score"] >= 31


def test_local_punycode_and_lookalike_detection():
    res_puny = analyze_url_locally("https://xn--pypal-4ve.com/signin")
    ids_puny = {i["id"] for i in res_puny["matched_indicators"]}
    assert "punycode_homograph" in ids_puny

    res_leet = analyze_url_locally("https://paypa1-secure.com/verify")
    ids_leet = {i["id"] for i in res_leet["matched_indicators"]}
    assert "lookalike_domain" in ids_leet


def test_local_shortener_labelled_destination_not_verified():
    res = analyze_url_locally("https://bit.ly/3xYzAbC")
    assert res["is_shortener"] is True
    assert "Destination not verified" in res["destination_status"]
    ids = {i["id"] for i in res["matched_indicators"]}
    assert "shortener_unverified" in ids
    # Shorteners must not have misleading external Safe Browsing lookup run on bit.ly root
    assert res["privacy_reduction"]["safe_browsing_eligible"] is False


def test_official_url_stays_low():
    res = analyze_url_locally("https://cybercrime.gov.in/")
    assert res["score"] <= 30
    assert res["category"]["label"] == "No known red flags"
    assert res["registrable_domain"] == "cybercrime.gov.in"


def test_privacy_reduction_strips_creds_query_fragment_and_tokens():
    sensitive_url = (
        "https://alice:secretpass@portal.example.co.in/verify/"
        "9f8e7d6c5b4a3210fedcba9876543210/step?otp=998877&email=alice@example.com#section"
    )
    prep = prepare_privacy_reduced_indicators(sensitive_url)
    assert prep["safe_browsing_eligible"] is True
    assert prep["stripped_sensitive_parts"] is True
    assert prep["registrable_domain"] == "example.co.in"
    preview = prep["reduced_url_preview"]
    assert "alice" not in preview
    assert "secretpass" not in preview
    assert "9f8e7d6c" not in preview
    assert "998877" not in preview
    assert "section" not in preview
    assert preview == "https://portal.example.co.in/verify/"
    # Every prefix must be exactly 4 bytes when decoded
    for p_b64 in prep["hash_prefixes_b64"]:
        assert len(base64.b64decode(p_b64)) == 4


def test_safe_browsing_v5_protobuf_decoding_and_match():
    expr = "evil.example/verify/"
    full_digest = hashlib.sha256(expr.encode("utf-8")).digest()
    prefix_b64 = base64.b64encode(full_digest[:4]).decode("ascii")
    full_b64 = base64.b64encode(full_digest).decode("ascii")

    # Build binary SearchHashesResponse protobuf
    detail_pb = _pb_varint(1, 2) + _pb_varint(2, 1)  # SOCIAL_ENGINEERING + CANARY
    full_hash_pb = _pb_bytes(1, full_digest) + _pb_bytes(2, detail_pb)
    duration_pb = _pb_varint(1, 300)
    response_pb = _pb_bytes(1, full_hash_pb) + _pb_bytes(2, duration_pb)

    decoded = decode_search_hashes_response(response_pb)
    assert decoded["cacheDuration"] == "300s"
    assert decoded["fullHashes"][0]["fullHash"] == full_b64
    assert decoded["fullHashes"][0]["fullHashDetails"][0]["threatType"] == "SOCIAL_ENGINEERING"

    captured_calls = []

    def fake_get(url, **kwargs):
        captured_calls.append((url, kwargs))
        assert kwargs.get("allow_redirects") is False
        return _DummyResponse(
            status_code=200,
            content=response_pb,
            headers={"Content-Type": "application/x-protobuf"},
        )

    sb_res = check_safe_browsing_v5(
        hash_prefixes_b64=[prefix_b64],
        candidate_full_hashes_b64=[full_b64],
        api_key="dummy-test-key",
        http_get=fake_get,
    )
    assert len(captured_calls) == 1
    assert captured_calls[0][0] == SAFE_BROWSING_V5_ENDPOINT
    assert sb_res["status"] == "matched"
    assert sb_res["matches"][0]["threat_type"] == "SOCIAL_ENGINEERING"
    assert "Google Safe Browsing" in sb_res["attribution"]


def test_safe_browsing_v5_missing_key_and_errors_never_marked_clean():
    missing = check_safe_browsing_v5(["AAAA"], ["A" * 44], api_key="")
    assert missing["status"] == "unavailable"
    assert missing["display_status"] == "Reputation information unavailable"
    assert missing["attribution"] is None

    def timeout_get(*_args, **_kwargs):
        raise requests.Timeout("timed out")

    timed_out = check_safe_browsing_v5(["AAAA"], ["A" * 44], api_key="k", http_get=timeout_get)
    assert timed_out["status"] == "unavailable"
    assert timed_out["display_status"] == "Reputation information unavailable"

    def quota_get(*_args, **_kwargs):
        return _DummyResponse(status_code=429, content=b"")

    quota = check_safe_browsing_v5(["AAAA"], ["A" * 44], api_key="k", http_get=quota_get)
    assert quota["status"] == "unavailable"
    assert quota["display_status"] == "Reputation information unavailable"


def test_rdap_receives_registrable_domain_only_and_handles_failures():
    seen_urls = []

    def fake_rdap_get(url, **kwargs):
        seen_urls.append(url)
        assert kwargs.get("allow_redirects") is False
        return _DummyResponse(
            status_code=200,
            json_data={
                "ldhName": "example.com",
                "status": ["active", "clientTransferProhibited"],
                "events": [
                    {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                    }
                ],
            },
        )

    rdap = lookup_rdap_domain("example.com", http_get=fake_rdap_get)
    assert seen_urls == ["https://rdap.org/domain/example.com"]
    assert rdap["status"] == "ok"
    assert rdap["registrar"] == "Example Registrar"
    assert rdap["age_days"] is not None

    def fail_get(*_args, **_kwargs):
        raise requests.ConnectionError("offline")

    failed = lookup_rdap_domain("example.com", http_get=fail_get)
    assert failed["status"] == "unavailable"
    assert failed["display_status"] == "Reputation information unavailable"


def test_consent_required_and_submitted_url_never_visited(client, monkeypatch, caplog):
    outbound_targets = []

    def spy_requests_get(url, **kwargs):
        outbound_targets.append(url)
        return _DummyResponse(status_code=503)

    monkeypatch.setattr(requests, "get", spy_requests_get)

    submitted_url = "https://sub.secret-victim-host.example/path?token=SECRET_TOKEN_123"
    with caplog.at_level(logging.INFO):
        res_no_consent = client.post(
            "/api/analyze-url",
            json={"url": submitted_url, "consent_external": False},
        )

    assert res_no_consent.status_code == 200
    data = res_no_consent.get_json()
    assert data["external_reputation"]["consent_granted"] is False
    assert outbound_targets == []
    # Full URL and query token must never appear in logs
    assert "SECRET_TOKEN_123" not in caplog.text
    assert "secret-victim-host.example" not in caplog.text


def test_consent_granted_never_contacts_submitted_host(client, monkeypatch):
    outbound_targets = []

    def spy_requests_get(url, **kwargs):
        outbound_targets.append(url)
        if "rdap.org" in url:
            return _DummyResponse(status_code=503)
        return _DummyResponse(status_code=200, json_data={"fullHashes": []})

    monkeypatch.setattr(requests, "get", spy_requests_get)

    res = client.post(
        "/api/analyze-url",
        json={
            "url": "https://login.victim-site-never-visit.example/auth/9f8e7d6c5b4a3210fedcba9876543210?secret=abc",
            "consent_external": True,
        },
    )
    assert res.status_code == 200
    assert all("victim-site-never-visit.example" not in target or target.startswith("https://rdap.org/domain/") for target in outbound_targets)
    assert not any(target.startswith("https://login.victim-site-never-visit.example") for target in outbound_targets)


def test_url_validation_rejects_malformed_and_non_http(client):
    for bad in ["", "   ", "javascript:alert(1)", "ftp://example.com/file", "not a url", "https://example.com/" + ("a" * 2100)]:
        with pytest.raises(UrlValidationError):
            analyze_url_locally(bad)

    res = client.post("/url-analyser", data={"url": "javascript:alert(1)"})
    assert res.status_code == 400
    assert "Only http:// and https:// URLs" in res.get_data(as_text=True)
