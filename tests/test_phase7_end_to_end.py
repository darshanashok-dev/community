"""Phase 7 tests: full end-to-end demonstration workflow, boundary cases, and evaluation framework."""

import csv
from pathlib import Path

import pytest
import requests

from app import create_app
from config import TestingConfig
from evaluation.evaluate_detection import evaluate_csv
from evaluation.split_dataset import compute_cohens_kappa, group_stratified_split

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def test_full_ten_step_demo_workflow_end_to_end(client, monkeypatch):
    # 1. Home page
    assert client.get("/").status_code == 200

    # 2. Suspicious phishing message
    phish = client.post(
        "/message-analyser",
        data={
            "channel": "sms",
            "message": (
                "URGENT: Your bank KYC is suspended today and your account will be blocked "
                "within 2 hours. Click http://example-verify.invalid/login and enter OTP and PAN."
            ),
        },
    )
    assert phish.status_code == 200
    assert "Strong scam signs" in phish.get_data(as_text=True)

    # 3. Digital-arrest scam message
    da = client.post(
        "/message-analyser",
        data={
            "channel": "whatsapp",
            "message": (
                "CBI officer calling: Aadhaar linked to money laundering parcel. "
                "Under digital arrest. Stay on video call, do not tell family, transfer to RBI safe account."
            ),
        },
    )
    assert da.status_code == 200
    da_html = da.get_data(as_text=True)
    assert "Digital-Arrest Coercion Pattern" in da_html
    assert 'href="/digital-arrest#call-checklist"' in da_html

    # 4. Suspicious URL without external consent
    url_local = client.post(
        "/url-analyser",
        data={"url": "http://sbi.co.in.kyc-verify.xyz/login?otp=1234"},
    )
    assert url_local.status_code == 200
    assert "External Checks Not Run" in url_local.get_data(as_text=True)

    # 5. External reputation lookup with explicit consent and simulated offline errors
    def offline_get(*_args, **_kwargs):
        raise requests.ConnectionError("offline")

    monkeypatch.setattr(requests, "get", offline_get)
    url_ext = client.post(
        "/url-analyser",
        data={"url": "https://cybercrime.gov.in/", "consent_external": "on"},
    )
    assert url_ext.status_code == 200
    assert "Reputation information unavailable" in url_ext.get_data(as_text=True)

    # 6. Android permission guide
    assert client.get("/android-guide").status_code == 200

    # 7. Digital-arrest call checklist
    chk = client.post(
        "/digital-arrest",
        data={"signs": ["authority_claim", "video_call_pressure", "secrecy_demand"]},
    )
    assert chk.status_code == 200
    assert "Strong Digital-Arrest Coercion Pattern Detected" in chk.get_data(as_text=True)

    # 8. After-scam assistance
    after = client.get("/after-scam")
    assert after.status_code == 200
    assert "You are not to blame." in after.get_data(as_text=True)

    # 9 & 10. Lessons & interactive quiz
    assert client.get("/learning").status_code == 200
    quiz = client.post("/learning", data={"answer_q1": "b", "answer_q2": "c"})
    assert quiz.status_code == 200
    assert "Your Score:" in quiz.get_data(as_text=True)


def test_boundary_input_lengths_accepted_and_rejected(client):
    max_msg = "Hello friend, meeting at 5 PM. " + ("a" * 4969)
    assert len(max_msg) == 5000
    ok_msg = client.post("/api/analyze-message", json={"channel": "sms", "message": max_msg})
    assert ok_msg.status_code == 200

    over_msg = max_msg + "z"
    bad_msg = client.post("/api/analyze-message", json={"channel": "sms", "message": over_msg})
    assert bad_msg.status_code == 400

    base_url = "https://example.com/"
    max_url = base_url + ("x" * (2048 - len(base_url)))
    assert len(max_url) == 2048
    ok_url = client.post("/api/analyze-url", json={"url": max_url, "consent_external": False})
    assert ok_url.status_code == 200

    over_url = max_url + "y"
    bad_url = client.post("/api/analyze-url", json={"url": over_url, "consent_external": False})
    assert bad_url.status_code == 400


def test_evaluation_group_split_prevents_template_leakage():
    samples_path = PROJECT_ROOT / "evaluation" / "synthetic_smoke_samples.csv"
    with samples_path.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    agreement = compute_cohens_kappa(rows)
    assert agreement["annotated_count"] == 24
    assert agreement["cohens_kappa"] == 1.0

    dev_rows, test_rows = group_stratified_split(rows, dev_ratio=0.70, seed=42)
    assert len(dev_rows) > 0
    assert len(test_rows) > 0
    assert len(dev_rows) + len(test_rows) == len(rows)

    dev_groups = {r["template_group_id"] for r in dev_rows}
    test_groups = {r["template_group_id"] for r in test_rows}
    assert dev_groups.isdisjoint(test_groups)


def test_evaluation_metrics_and_baseline_comparison_on_synthetic_smoke():
    samples_path = PROJECT_ROOT / "evaluation" / "synthetic_smoke_samples.csv"
    report = evaluate_csv(samples_path, score_threshold=31)

    assert report["total_samples"] == 24
    assert report["dataset_origins"] == {"synthetic_dev": 24}
    assert len(report["rules_sha256"]) == 64

    rule_eng = report["contextual_rule_engine"]
    baseline = report["keyword_only_baseline"]
    assert rule_eng["class_counts"] == {"scam_positive": 12, "benign_negative": 12}
    # Contextual rule engine should have much lower false-positive rate than naive keyword matching
    assert rule_eng["false_positive_rate"] < baseline["false_positive_rate"]
    assert rule_eng["f1_score"] > baseline["f1_score"]
