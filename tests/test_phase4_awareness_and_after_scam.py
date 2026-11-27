"""Phase 4 tests: digital-arrest awareness, interactive call checklist, and after-scam guidance."""

import pytest

from app import create_app
from app.services.digital_arrest_service import (
    ChecklistValidationError,
    evaluate_call_checklist,
)
from config import TestingConfig


@pytest.fixture()
def client():
    app = create_app(TestingConfig)
    return app.test_client()


def test_digital_arrest_page_contains_required_explanations(client):
    res = client.get("/digital-arrest")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    for phrase in [
        "Government &amp; Regulator Impersonation",
        "Police, CBI &amp; Court Impersonation",
        "Fear &amp; Artificial Urgency",
        "Video-Call Pressure &amp; Surveillance",
        "Secrecy &amp; Isolation Instructions",
        "Safe-Account",
        "Digital-Arrest Call Checklist",
    ]:
        assert phrase in html


def test_call_checklist_service_levels():
    empty_res = evaluate_call_checklist([])
    assert empty_res["selected_count"] == 0
    assert empty_res["level"] == "none_selected"

    single_non_critical = evaluate_call_checklist(["authority_claim", "unknown_ignored_id"])
    assert single_non_critical["selected_count"] == 1
    assert single_non_critical["level"] == "warning_signs_present"
    assert single_non_critical["show_after_scam_cta"] is True

    critical_combo = evaluate_call_checklist(
        ["authority_claim", "video_call_pressure", "secrecy_demand", "safe_account_transfer"]
    )
    assert critical_combo["selected_count"] == 4
    assert critical_combo["level"] == "strong_digital_arrest_pattern"
    assert "Strong Digital-Arrest Coercion Pattern Detected" in critical_combo["headline"]

    with pytest.raises(ChecklistValidationError):
        evaluate_call_checklist("not-a-list")  # type: ignore[arg-type]


def test_digital_arrest_checklist_post_and_api(client):
    res = client.post(
        "/digital-arrest",
        data={"signs": ["arrest_threat", "secrecy_demand", "safe_account_transfer"]},
    )
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "Strong Digital-Arrest Coercion Pattern Detected" in html
    assert "Open After-Scam Assistance" in html

    api_res = client.post(
        "/api/digital-arrest-checklist",
        json={"signs": ["video_call_pressure"]},
    )
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert data["selected_count"] == 1
    assert data["level"] == "strong_digital_arrest_pattern"


def test_after_scam_page_ordered_guidance_and_supportive_wording(client):
    res = client.get("/after-scam")
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert "You are not to blame." in html

    ordered_markers = [
        "Call 1930 immediately",
        "Report through cybercrime.gov.in",
        "Contact your bank immediately",
        "Preserve transaction records",
        "Retain relevant messages and evidence",
        "Follow up through appropriate official channels",
    ]
    positions = [html.index(marker) for marker in ordered_markers]
    assert positions == sorted(positions)


def test_message_analyser_links_to_checklist_and_after_scam(client):
    res = client.post(
        "/message-analyser",
        data={
            "channel": "whatsapp",
            "message": "CBI officer says digital arrest warrant issued. Stay on video call and do not tell anyone.",
        },
    )
    assert res.status_code == 200
    html = res.get_data(as_text=True)
    assert 'href="/digital-arrest#call-checklist"' in html
    assert 'href="/after-scam"' in html
