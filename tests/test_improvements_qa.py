"""Regression and QA tests for Priority 1-9 improvements."""

import csv
from pathlib import Path

import pytest

from app import create_app
from app.services.message_analyser import analyze_message
from app.services.url_analyser import analyze_url_locally, extract_registrable_domain
from config import TestingConfig
from evaluation.dataset_validator import DatasetValidationError, validate_dataset_rows
from evaluation.evaluate_detection import evaluate_csv

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


@pytest.mark.parametrize(
    "host, expected",
    [
        ("example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("example.co.nz", "example.co.nz"),
        ("example.com.mx", "example.com.mx"),
        ("example.co.in", "example.co.in"),
        ("subdomain.example.co.uk", "example.co.uk"),
        ("sub.xn--bcher-kva.de", "xn--bcher-kva.de"),
        ("xn--80ak6aa92e.com", "xn--80ak6aa92e.com"),
        ("192.0.2.1", None),
        ("::1", None),
        ("co.uk", None),
        ("com.mx", None),
        ("com", None),
        ("localhost", None),
        ("bad..domain.com", None),
    ],
)
def test_psl_registrable_domain_extraction(host, expected):
    assert extract_registrable_domain(host) == expected


def test_bare_public_suffix_url_flagged_locally():
    res = analyze_url_locally("https://co.uk/login")
    ids = {i["id"] for i in res["matched_indicators"]}
    assert "invalid_or_public_suffix_host" in ids
    assert res["registrable_domain"] is None


def test_message_analyser_regressions_and_score_breakdown():
    # Zero-width obfuscation evasion attempt
    obfuscated = "CBI officer: you are under digital a\u200brrest. Share O\u200bTP now."
    res_obf = analyze_message(obfuscated, channel="whatsapp")
    assert res_obf["score"] >= 66
    assert res_obf["score_breakdown"]["final_score"] == res_obf["score"]

    # Doorstep delivery PIN notice must remain low risk
    delivery = (
        "Your order #402-1122334 is out for delivery today. "
        "Share OTP 4412 with delivery agent only when receiving parcel."
    )
    res_del = analyze_message(delivery, channel="sms")
    assert res_del["score"] <= 30
    assert res_del["category"]["label"] == "No known red flags"

    # KYC phishing with bank name + enter OTP must score Strong scam signs
    kyc = (
        "Dear user, your SBI KYC is pending and account will be suspended within 2 hours. "
        "Update immediately at http://sbi-kyc-update.xyz/login and enter OTP."
    )
    res_kyc = analyze_message(kyc, channel="sms")
    assert res_kyc["score"] >= 66
    assert res_kyc["category"]["label"] == "Strong scam signs"

    # Impersonation + transaction phrasing must not receive benign credit
    spoof = (
        "CBI official notice: Rs. 5000 debited from A/c XX1234. "
        "Reply with your OTP to avoid legal action."
    )
    res_spoof = analyze_message(spoof, channel="sms")
    assert res_spoof["benign_contexts"] == []
    assert len(res_spoof["recommended_actions"]) == len(set(res_spoof["recommended_actions"]))


def test_evaluation_blocks_synthetic_and_unmet_genuine_requirements():
    smoke_csv = PROJECT_ROOT / "evaluation" / "synthetic_smoke_samples.csv"
    with pytest.raises(DatasetValidationError):
        evaluate_csv(smoke_csv, mode="genuine-eval")

    # Test PII detection & disagreement-notes enforcement
    bad_rows = [
        {
            "sample_id": "G-1",
            "dataset_origin": "genuine_eval",
            "source_type": "bank_alert",
            "source_provenance": "public",
            "license_or_permission": "cc0",
            "template_group_id": "T1",
            "channel": "sms",
            "redacted_text": "Call 9876543210 or email test@example.com immediately.",
            "annotator_1_label": "scam",
            "annotator_2_label": "benign",
            "adjudicated_label": "scam",
            "disagreement_notes": "",
        }
    ]
    with pytest.raises(DatasetValidationError) as exc_info:
        validate_dataset_rows(bad_rows, mode="genuine-eval")
    msg = str(exc_info.value)
    assert "unredacted PII" in msg
    assert "disagreement_notes" in msg
    assert "minimum 300 required" in msg
    assert "minimum 100 required" in msg


def test_ui_polish_user_facing_labels_and_score_breakdown(client):
    home_html = client.get("/").get_data(as_text=True)
    assert "Phase 2 Engine" not in home_html
    assert "Phase 3 Engine" not in home_html

    msg_res = client.post(
        "/message-analyser",
        data={
            "channel": "sms",
            "message": "URGENT: SBI KYC suspended, enter OTP at http://fake.invalid/login",
        },
    )
    msg_html = msg_res.get_data(as_text=True)
    assert "Indicator Points" in msg_html
    assert "Context Combinations" in msg_html
    assert "Benign Context Offset" in msg_html
