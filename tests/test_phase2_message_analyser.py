"""Phase 2 tests: contextual message analysis, false-positive control, validation, and privacy."""

import logging

import pytest

from app import create_app
from app.services.message_analyser import MessageValidationError, analyze_message
from config import TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def test_digital_arrest_scam_scores_high():
    text = (
        "This is CBI Cyber Crime Officer calling. Your Aadhaar is linked to a "
        "money laundering parcel with illegal drugs. A non-bailable arrest warrant "
        "is issued and you are under digital arrest. Stay on WhatsApp video call, "
        "do not tell family or anyone, and transfer Rs. 50,000 to RBI safe account."
    )
    res = analyze_message(text, channel="whatsapp")
    assert res["score"] >= 66
    assert res["category"]["label"] == "Strong scam signs"
    assert res["has_digital_arrest_signs"] is True
    indicator_ids = {item["id"] for item in res["matched_indicators"]}
    assert {"impersonation", "arrest_threat", "legal_intimidation", "secrecy", "video_call_pressure", "safe_account"} <= indicator_ids
    combo_ids = {c["id"] for c in res["matched_combinations"]}
    assert "combo_digital_arrest" in combo_ids
    assert len(res["recommended_actions"]) >= 2


def test_phishing_kyc_sms_scores_high():
    text = (
        "URGENT: Your KYC department notice - account will be blocked within 2 hours. "
        "Click http://kyc-update.invalid/verify and share your OTP and PAN card immediately."
    )
    res = analyze_message(text, channel="sms")
    assert res["score"] >= 66
    assert res["category"]["label"] == "Strong scam signs"
    combo_ids = {c["id"] for c in res["matched_combinations"]}
    assert "combo_credential_phishing" in combo_ids


def test_ambiguous_message_scores_medium():
    text = (
        "Your KYC department requires verification within 24 hours. "
        "Please contact on 9876543210 to avoid account restriction."
    )
    res = analyze_message(text, channel="sms")
    assert 31 <= res["score"] <= 65
    assert res["category"]["label"] == "Some warning signs"


@pytest.mark.parametrize(
    "benign_text",
    [
        "Your OTP for HDFC NetBanking login is 482910. Valid for 5 minutes. Do not share this OTP with anyone.",
        "Rs. 1,250.00 debited from A/c XX4321 on 27-Nov-26 via UPI Ref 633199012345. Avl Bal Rs. 14,820.50. If not done by you, call bank helpline.",
        "Rs. 5,000.00 credited to A/c XX8812 via UPI ID user@okbank. Available balance Rs. 21,300.00.",
        "Your order #IN98421 is out for delivery today. Our delivery partner will reach you soon. Track on official app.",
        "Hey, are we still meeting for lunch at 1:30 PM near the library?",
        "Your OTP is 771122.",
        "Urgent: Please review the lab assignment slides before tomorrow's class.",
    ],
)
def test_benign_and_isolated_keyword_messages_stay_low(benign_text):
    res = analyze_message(benign_text, channel="sms")
    assert res["score"] <= 30, f"Unexpectedly high score {res['score']} for: {benign_text}"
    assert res["category"]["label"] == "No known red flags"


def test_adversarial_do_not_share_plus_enter_otp_on_link():
    text = (
        "Do not share with friends, enter your OTP on this link http://fake.invalid/otp "
        "within 10 minutes or your account will be suspended."
    )
    res = analyze_message(text, channel="sms")
    indicator_ids = {item["id"] for item in res["matched_indicators"]}
    assert "otp_password_request" in indicator_ids
    assert res["score"] >= 31


def test_input_validation_errors():
    with pytest.raises(MessageValidationError):
        analyze_message("")
    with pytest.raises(MessageValidationError):
        analyze_message("   \n\t  ")
    with pytest.raises(MessageValidationError):
        analyze_message("Hello", channel="telegram")
    with pytest.raises(MessageValidationError):
        analyze_message("a" * 5001, max_length=5000)


def test_flask_post_message_analyser_page(client):
    res = client.post(
        "/message-analyser",
        data={
            "channel": "whatsapp",
            "message": "CBI officer says digital arrest warrant issued. Stay on video call and do not tell family.",
        },
    )
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Strong scam signs" in html
    assert "Advisory &amp; Privacy Notice" in html
    assert "Open Digital-Arrest Guidance" in html


def test_flask_post_message_analyser_validation_error(client):
    res = client.post(
        "/message-analyser",
        data={"channel": "sms", "message": "   "},
    )
    assert res.status_code == 400
    assert "Message text cannot be empty." in res.get_data(as_text=True)


def test_api_analyze_message_endpoint(client):
    res = client.post(
        "/api/analyze-message",
        json={
            "channel": "email",
            "message": "Your parcel is arriving today. Track on official app.",
        },
    )
    assert res.status_code == 200
    data = res.get_json()
    assert data["score"] <= 30
    assert data["category"]["label"] == "No known red flags"


def test_api_analyze_message_rejects_oversized_payload(client):
    res = client.post(
        "/api/analyze-message",
        json={"channel": "sms", "message": "x" * 6000},
    )
    assert res.status_code == 400
    assert "maximum allowed length" in res.get_json()["error"]


def test_submitted_message_not_logged(client, caplog):
    secret_marker = "UNIQUE_SENSITIVE_MARKER_99182736"
    with caplog.at_level(logging.INFO):
        res = client.post(
            "/message-analyser",
            data={"channel": "sms", "message": f"Your OTP is 1234 {secret_marker}"},
        )
    assert res.status_code == 200
    assert secret_marker not in caplog.text
    # Submitted raw message should also not be echoed back in rendered HTML
    assert secret_marker not in res.get_data(as_text=True)
