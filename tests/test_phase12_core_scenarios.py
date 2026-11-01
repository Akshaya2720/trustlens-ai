"""TrustLens AI - Phase 12: Core Scenarios Verification Test Suite

Verifies the 8 mandatory end-to-end core scenarios across the entire multimodal system:
1. Financial scam message (demands money/crypto/gift cards)
2. Phishing URL screenshot (brand impersonation & credential theft via OCR)
3. Urgent voice note (coercion, fake authority, arrest threat)
4. Malicious URL inspection (threat intelligence detection)
5. Debunked false public claim (fact-checking verification)
6. Cross-modal contradiction (text claims legitimate, visual reveals phishing destination)
7. Benign communication (routine message, zero false-positive)
8. External provider failure (graceful fallback without service interruption)
"""

import io
from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from PIL import Image, ImageDraw

from app.agents.evidence_analysis import EvidenceAnalysisAgent
from app.clients.meta_client import (
    MetaResponseMetadata,
    MetaTranscriptionResponse,
    TranscriptionSegment,
    meta_client,
)
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.schemas.agent_outputs import (
    ContentIntelligenceOutput,
    EvidenceAnalysisOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.services.risk_engine import DeterministicRiskEngine


def make_test_image_with_text(text: str, width: int = 700, height: int = 150) -> bytes:
    """Generates a synthetic test image with clean text rendered on a white background."""
    img = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    lines = text.split("\n")
    y = 15
    for line in lines:
        draw.text((20, y), line, fill=(0, 0, 0))
        y += 35
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def make_test_wav_bytes() -> bytes:
    """44-byte standard valid PCM WAV header."""
    buf = io.BytesIO()
    buf.write(b"RIFF")
    buf.write((36).to_bytes(4, "little"))
    buf.write(b"WAVE")
    buf.write(b"fmt ")
    buf.write((16).to_bytes(4, "little"))
    buf.write((1).to_bytes(2, "little"))
    buf.write((1).to_bytes(2, "little"))
    buf.write((8000).to_bytes(4, "little"))
    buf.write((16000).to_bytes(4, "little"))
    buf.write((2).to_bytes(2, "little"))
    buf.write((16).to_bytes(2, "little"))
    buf.write(b"data")
    buf.write((0).to_bytes(4, "little"))
    return buf.getvalue()


# Scenario 1: Financial Scam Message
@pytest.mark.asyncio
async def test_scenario_1_financial_scam_message(client: AsyncClient):
    payload = {
        "text": "IRS Urgent Notice: You have an unpaid federal tax balance of $4,820. An arrest warrant will be issued in 2 hours unless payment is settled immediately via Bitcoin or Apple Gift Cards.",
        "sender_hint": "Internal Revenue Service",
    }
    resp = await client.post("/api/v1/investigations/text", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["final_risk_level"] in ("high", "critical")
    assert data["final_risk_score"] >= 60.0
    assert any("arrest" in ind.lower() or "extortion" in ind.lower() or "urgency" in ind.lower() or "scam" in ind.lower() or "impersonation" in ind.lower() for ind in data["observed_indicators"])


# Scenario 2: Phishing Screenshot
@pytest.mark.asyncio
async def test_scenario_2_phishing_screenshot(client: AsyncClient):
    img_bytes = make_test_image_with_text(
        "CHASE ONLINE BANKING: Your account is suspended.\nVerify at http://chase-login-verify.xyz immediately."
    )
    files = {"file": ("chase_alert.png", img_bytes, "image/png")}
    data_form = {"context_notes": "Received via MMS"}
    resp = await client.post("/api/v1/investigations/image", files=files, data=data_form)
    assert resp.status_code == 201
    data = resp.json()
    assert data["status"] == "completed"
    assert data["final_risk_level"] in ("medium", "high", "critical", "unknown")
    assert len(data["artifacts"]) >= 1


# Scenario 3: Urgent Voice Note
@pytest.mark.asyncio
async def test_scenario_3_urgent_voice_note(client: AsyncClient):
    wav_bytes = make_test_wav_bytes()
    transcript_text = (
        "Internal Revenue Service notice. You have unpaid taxes of 450 dollars. "
        "Pay immediately at http://irs-tax-relief.fake or face police action within 24 hours."
    )
    mock_trans_resp = MetaTranscriptionResponse(
        text=transcript_text,
        language="en",
        duration_seconds=5.2,
        segments=[
            TranscriptionSegment(start=0.0, end=5.2, text=transcript_text, speaker="Speaker 1"),
        ],
        metadata=MetaResponseMetadata(model_id="muse-voice-transcribe-1.0", latency_ms=80.0),
    )

    with patch.object(meta_client, "api_key", "test_key"):
        with patch.object(meta_client, "transcribe_audio", AsyncMock(return_value=mock_trans_resp)):
            with patch.object(meta_client, "generate_structured", AsyncMock(side_effect=Exception("offline test"))):
                files = {"file": ("voicemail.wav", wav_bytes, "audio/wav")}
                resp = await client.post("/api/v1/investigations/audio", files=files)
                assert resp.status_code == 201
                data = resp.json()
                assert data["transcription"] == transcript_text
                assert data["final_risk_level"] in ("medium", "high", "critical")
                assert data["final_risk_score"] >= 40.0


# Scenario 4: Malicious URL Inspection
@pytest.mark.asyncio
async def test_scenario_4_malicious_url_inspection(client: AsyncClient):
    payload = {"url": "http://185.220.101.5/malware/bin/payload.exe"}
    resp = await client.post("/api/v1/investigations/url", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["final_risk_level"] in ("medium", "high", "critical")
    assert data["final_risk_score"] >= 40.0


# Scenario 5: Debunked False Public Claim
@pytest.mark.asyncio
async def test_scenario_5_debunked_false_claim(client: AsyncClient):
    payload = {
        "claim_text": "Government executive order granting $5,000 cash subsidy or relief to all citizens.",
        "context_notes": "Viral WhatsApp forwarded broadcast message"
    }
    resp = await client.post("/api/v1/investigations/claim", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["final_risk_level"] in ("high", "critical")
    assert data["final_risk_score"] >= 65.0
    assert len(data["verified_claims"]) >= 1


# Scenario 6: Cross-Modal Contradiction
@pytest.mark.asyncio
async def test_scenario_6_cross_modal_contradiction():
    # Direct cross-modal verification: Text claims legitimate bank, screenshot reveals malicious destination
    content_intel = ContentIntelligenceOutput(categories=["possible_impersonation"])
    impersonation = ImpersonationAnalysisOutput(
        claimed_organization="Bank of America",
        sender_domain_or_address="bankofamerica.com",
    )
    image_analysis = {
        "primary_organization": "Phish Portal",
        "visible_urls": ["http://phish-secure-portal.xyz/login"],
    }
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["http://phish-secure-portal.xyz/login"],
        malicious_urls=["http://phish-secure-portal.xyz/login"],
    )

    ev_output = await EvidenceAnalysisAgent.analyze(
        content_intel=content_intel,
        threat_intel=threat_intel,
        impersonation=impersonation,
        image_analysis=image_analysis,
        raw_text="Official notice from https://www.bankofamerica.com regarding your account balance.",
        extracted_urls=["https://www.bankofamerica.com"],
    )

    assert len(ev_output.contradictions) >= 1
    assert any("Cross-Modal Contradiction" in c for c in ev_output.contradictions)

    # Risk Engine calculates risk floor for cross-modal contradiction
    risk_assessment = DeterministicRiskEngine.calculate_risk(
        evidence_records=[],
        scam_detection=None,
        impersonation=impersonation,
        discrepancies=ev_output.contradictions,
    )
    assert risk_assessment.risk_score >= 65.0
    assert risk_assessment.risk_level in ("high", "critical")
    assert any("contradiction" in ind.lower() or "inconsistency" in ind.lower() for ind in risk_assessment.indicators)


# Scenario 7: Benign Communication
@pytest.mark.asyncio
async def test_scenario_7_benign_communication(client: AsyncClient):
    payload = {
        "text": "Your appointment with Dr. Henderson is confirmed for Thursday, November 5th at 2:30 PM. Please arrive 10 minutes early. Reply STOP to unsubscribe.",
        "sender_hint": "Henderson Clinic",
    }
    resp = await client.post("/api/v1/investigations/text", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["final_risk_level"] == "low"
    assert data["final_risk_score"] == 0.0


# Scenario 8: External Provider Outage Fallback
@pytest.mark.asyncio
async def test_scenario_8_external_provider_outage_fallback(client: AsyncClient):
    with patch("app.clients.threat_intel.virustotal.VirusTotalClient.check_url") as mock_vt:
        # Simulate network timeout / 503 outage
        mock_vt.return_value = NormalizedEvidenceRecord(
            provider_name="VirusTotal",
            query_type="url",
            query_target="https://unreachable-provider-test.com",
            status=ProviderStatus.UNAVAILABLE,
            error_message="VirusTotal upstream service timeout (503 Service Unavailable)",
        )
        payload = {"url": "https://unreachable-provider-test.com"}
        resp = await client.post("/api/v1/investigations/url", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["status"] == "completed"
        assert any("VirusTotal" in lim for lim in data["limitations"])
