"""Regression and QA tests for Priority 1-9 improvements."""

import csv
from pathlib import Path

import pytest

from app import create_app
from app.services.message_analyser import analyze_message
from app.services.url_analyser import analyze_url_locally, extract_registrable_domain
from config import TestingConfig
from evaluation.analyze_usability import UsabilityValidationError, summarize_usability_csv
from evaluation.dataset_validator import DatasetValidationError, validate_dataset_rows
from evaluation.evaluate_detection import evaluate_csv
from evaluation.split_dataset import compute_cohens_kappa, find_near_duplicate_crossings

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
        ("a.b.c.d.example.co.uk", "example.co.uk"),
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


def test_usability_summary_blocks_template_and_computes_means(tmp_path):
    template_csv = PROJECT_ROOT / "evaluation" / "usability_questionnaire_template.csv"
    with pytest.raises(UsabilityValidationError):
        summarize_usability_csv(template_csv)

    sample_csv = tmp_path / "usability_test.csv"
    sample_csv.write_text(
        "participant_code,consent_confirmed,age_bracket,digital_comfort_1_to_5,"
        "task1_clarity_1_to_5,task2_benign_confidence_1_to_5,task3_url_clarity_1_to_5,"
        "task4_checklist_clarity_1_to_5,task5_android_quiz_clarity_1_to_5,"
        "understands_advisory_disclaimer,overall_ease_1_to_5,anonymous_observations\n"
        "P01,yes,18-29,4,5,4,5,5,4,yes,5,Clear score cards\n"
        "P02,yes,50+,2,4,4,4,5,4,yes,4,Helpful after-scam steps\n",
        encoding="utf-8",
    )
    summary = summarize_usability_csv(sample_csv)
    assert summary["participant_count"] == 2
    assert summary["meets_target_sample_size"] is False
    assert summary["mean_likert_scores_1_to_5"]["task1_clarity_1_to_5"] == 4.5
    assert summary["observation_count"] == 2


def test_rdap_receives_psl_registrable_domain_for_multipart_tlds(client, monkeypatch):
    import requests

    seen_urls: list[str] = []

    class _DummyResp:
        def __init__(self, status_code=200, json_data=None):
            self.status_code = status_code
            self._json = json_data
            self.content = b"{}"
            self.headers = {"Content-Type": "application/json"}

        def json(self):
            return self._json

    def spy_get(url, **_kwargs):
        seen_urls.append(url)
        if "rdap.org" in url:
            return _DummyResp(200, {"ldhName": url.rsplit("/", 1)[-1], "events": [], "status": ["active"]})
        return _DummyResp(200, {"fullHashes": []})

    monkeypatch.setattr(requests, "get", spy_get)
    for url, expected_reg in [
        ("https://a.b.example.co.uk/login", "example.co.uk"),
        ("https://portal.example.co.nz/pay", "example.co.nz"),
        ("https://auth.example.com.mx/verify", "example.com.mx"),
    ]:
        res = client.post("/api/analyze-url", json={"url": url, "consent_external": True})
        assert res.status_code == 200
        assert res.get_json()["local_analysis"]["registrable_domain"] == expected_reg
        assert f"https://rdap.org/domain/{expected_reg}" in seen_urls


def test_annotation_template_has_no_prefilled_rows_and_kappa_reports_all_counts():
    template_path = PROJECT_ROOT / "evaluation" / "annotation_template.csv"
    with template_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows == []

    kappa_stats = compute_cohens_kappa(
        [
            {"annotator_1_label": "scam", "annotator_2_label": "scam"},
            {"annotator_1_label": "benign", "annotator_2_label": "benign"},
            {"annotator_1_label": "scam", "annotator_2_label": "benign"},
            {"annotator_1_label": "scam", "annotator_2_label": ""},
        ]
    )
    assert kappa_stats["annotated_count"] == 3
    assert kappa_stats["agreement_count"] == 2
    assert kappa_stats["disagreement_count"] == 1
    assert kappa_stats["missing_annotation_count"] == 1
    assert kappa_stats["cohens_kappa"] is not None

    near_dups = find_near_duplicate_crossings(
        [{"sample_id": "D1", "redacted_text": "Your bank KYC is suspended today click link to verify"}],
        [{"sample_id": "T1", "redacted_text": "Your bank KYC is suspended today click link to verify now"}],
        threshold=0.85,
    )
    assert len(near_dups) == 1
