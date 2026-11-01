"""TrustLens AI - Phase 9: Evidence-Grounded Q&A Assistant Tests

Verifies:
1. Strict grounding in investigation artifacts and external evidence records.
2. Direct references to specific evidence record IDs and artifact identifiers.
3. Explicit refusal, disclaimers, and notices when requested information is absent.
4. Zero hallucination guarantee on out-of-scope inquiries.
5. Integration with POST /api/v1/investigations/{investigation_id}/questions.
"""

import pytest
from httpx import AsyncClient
from unittest.mock import AsyncMock

from app.clients.meta_client import MetaModelClient
from app.db.models import Artifact, ExternalEvidence, Investigation, RiskAssessment
from app.services.evidence_qa import EvidenceQAService, GroundedQAOutput


@pytest.fixture
def sample_investigation():
    """Builds a rich mock investigation object for testing evidence QA."""
    inv = Investigation(
        id="inv-test-9999",
        input_type="multimodal",
        status="completed",
        final_risk_level="critical",
        final_risk_score=90.0,
        confidence=0.88,
        summary="High-risk phishing campaign impersonating Chase Bank with confirmed malicious destination URL.",
    )
    inv.artifacts = [
        Artifact(
            id="art-img-1",
            investigation_id="inv-test-9999",
            artifact_type="image",
            filename="chase_phish.png",
            ocr_text="URGENT: Chase Online Banking Security Alert. Click http://chase-update-security.xyz to restore access.",
        )
    ]
    inv.external_evidence = [
        ExternalEvidence(
            id="ev-vt-1",
            investigation_id="inv-test-9999",
            provider_name="VirusTotal",
            query_type="url",
            query_target="http://chase-update-security.xyz",
            raw_status="ok",
            is_malicious=True,
            threat_description="14/90 security vendors flagged as phishing",
            source_reference="https://www.virustotal.com/gui/url/mocked",
        ),
        ExternalEvidence(
            id="ev-pt-1",
            investigation_id="inv-test-9999",
            provider_name="PhishTank",
            query_type="url",
            query_target="http://chase-update-security.xyz",
            raw_status="confirmed_match",
            is_malicious=True,
            threat_description="Verified phishing page targeting Chase Online banking credentials",
            source_reference="https://phishtank.org/phish_detail.php?phish_id=123",
        ),
    ]
    inv.risk_assessment = RiskAssessment(
        id="ra-1",
        investigation_id="inv-test-9999",
        risk_score=90.0,
        risk_level="critical",
        confidence=0.88,
        indicators=[
            "Confirmed malicious URL flagged by multiple threat intelligence engines",
            "Brand impersonation of Chase Bank in visual and extracted content",
            "High urgency and credential harvesting language",
        ],
        contradictions=[],
        limitations=["Domain registration creation timestamp could not be verified"],
        recommendations=[
            "DO NOT click http://chase-update-security.xyz",
            "Do NOT input banking credentials or passwords",
            "Report phishing to abuse@chase.com",
        ],
        score_breakdown={
            "confirmed_phishing": 55.0,
            "domain_impersonation": 35.0,
        },
    )
    inv.claims = []
    return inv


@pytest.mark.asyncio
async def test_evidence_qa_risk_inquiry(sample_investigation):
    """Verifies inquiry about risk level directly cites risk score, indicators, and malicious evidence IDs."""
    client = MetaModelClient(api_key=None)  # unconfigured, triggers deterministic QA
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="What is the risk level and why was it scored this way?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is True
    assert res.groundedness_assessment == "fully_grounded"
    assert "CRITICAL" in res.answer
    assert "90.0" in res.answer or "90" in res.answer
    assert "ev-vt-1" in res.referenced_evidence_ids
    assert "ev-pt-1" in res.referenced_evidence_ids
    assert res.missing_information_notice is None
    assert res.confidence >= 0.85


@pytest.mark.asyncio
async def test_evidence_qa_url_threat_intel_inquiry(sample_investigation):
    """Verifies inquiry about URLs returns specific provider verdicts and references evidence IDs."""
    client = MetaModelClient(api_key=None)
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="Did VirusTotal or PhishTank find any malicious URLs in this message?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is True
    assert res.groundedness_assessment == "fully_grounded"
    assert "VirusTotal" in res.answer
    assert "PhishTank" in res.answer
    assert "http://chase-update-security.xyz" in res.answer
    assert "ev-vt-1" in res.referenced_evidence_ids
    assert "ev-pt-1" in res.referenced_evidence_ids


@pytest.mark.asyncio
async def test_evidence_qa_screenshot_ocr_inquiry(sample_investigation):
    """Verifies inquiry about image/screenshot returns OCR text and artifact ID."""
    client = MetaModelClient(api_key=None)
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="What text was extracted from the screenshot?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is True
    assert res.groundedness_assessment == "fully_grounded"
    assert "Chase Online Banking Security Alert" in res.answer
    assert "art-img-1" in res.referenced_evidence_ids


@pytest.mark.asyncio
async def test_evidence_qa_unsubmitted_audio_refusal(sample_investigation):
    """Verifies inquiry about audio when no audio was uploaded explicitly states absence."""
    client = MetaModelClient(api_key=None)
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="What was said in the audio voice recording?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is False
    assert res.groundedness_assessment == "unsupported"
    assert "No audio recording" in res.answer or "not part of the evidence" in res.answer
    assert res.missing_information_notice is not None
    assert "audio" in res.missing_information_notice.lower()


@pytest.mark.asyncio
async def test_evidence_qa_out_of_scope_inquiry_refusal(sample_investigation):
    """Verifies completely absent or irrelevant trivia is explicitly refused with no hallucination."""
    client = MetaModelClient(api_key=None)
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="What is the current stock price of Apple, and who was the sender's high school teacher?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is False
    assert res.groundedness_assessment == "unsupported"
    assert "not part of the evidence gathered" in res.answer
    assert res.missing_information_notice is not None
    assert res.referenced_evidence_ids == []
    assert res.confidence == 0.0


@pytest.mark.asyncio
async def test_evidence_qa_recommended_actions_inquiry(sample_investigation):
    """Verifies inquiry about recommended next steps cites safety actions."""
    client = MetaModelClient(api_key=None)
    res: GroundedQAOutput = await EvidenceQAService.answer_question(
        inv=sample_investigation,
        question="What recommended actions should I take to protect myself?",
        meta_client=client,
    )

    assert res.grounded_in_evidence is True
    assert res.groundedness_assessment == "fully_grounded"
    assert "DO NOT click" in res.answer
    assert "banking credentials" in res.answer


@pytest.mark.asyncio
async def test_api_investigation_question_endpoint(client: AsyncClient):
    """End-to-end integration test creating a text investigation and querying the Q&A endpoint."""
    # 1. Create text investigation
    post_resp = await client.post(
        "/api/v1/investigations/text",
        json={
            "text": "CRITICAL ALERT: Your Bank of America debit card is frozen. Verify immediately at http://secure-bofa-login.top to unfreeze.",
            "sender_hint": "BofA Security Alert",
        },
    )
    assert post_resp.status_code == 201
    inv_data = post_resp.json()
    inv_id = inv_data["investigation_id"]

    # 2. Ask a grounded question about risk
    q1_resp = await client.post(
        f"/api/v1/investigations/{inv_id}/questions",
        json={"question": "What is the final risk level and score for this investigation?"},
    )
    assert q1_resp.status_code == 200
    q1_data = q1_resp.json()
    assert q1_data["investigation_id"] == inv_id
    assert q1_data["grounded_in_evidence"] is True
    assert q1_data["groundedness_assessment"] == "fully_grounded"
    assert len(q1_data["answer"]) > 0

    # 3. Ask an out-of-scope question
    q2_resp = await client.post(
        f"/api/v1/investigations/{inv_id}/questions",
        json={"question": "What is the weather in Tokyo tomorrow?"},
    )
    assert q2_resp.status_code == 200
    q2_data = q2_resp.json()
    assert q2_data["investigation_id"] == inv_id
    assert q2_data["groundedness_assessment"] == "unsupported"
    assert q2_data["missing_information_notice"] is not None
    assert "not part of the evidence" in q2_data["answer"].lower()
