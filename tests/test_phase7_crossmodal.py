"""TrustLens AI - Phase 7 Cross-Modal Investigation Tests

Verifies cross-modal processing, multi-channel correlation, and contradiction detection:
- Combining text, images, audio recordings, and URLs in unified investigations
- Cross-modal contradiction detection (Text vs Visual, Audio vs Visual, Verbal vs URL)
- Coordinated multi-channel brand impersonation corroboration
- Complete artifact hashing and unified report generation
"""

import io
from PIL import Image
import pytest
from httpx import AsyncClient
from app.agents.evidence_analysis import EvidenceAnalysisAgent
from app.schemas.agent_outputs import (
    ContentIntelligenceOutput,
    EvidenceAnalysisOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)


def create_test_image(text_brand: str = "PayPal") -> bytes:
    img = Image.new("RGB", (300, 100), color=(255, 255, 255))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def create_test_wav_audio() -> bytes:
    # 44-byte standard PCM WAV header
    buf = io.BytesIO()
    buf.write(b"RIFF")
    buf.write((36).to_bytes(4, "little"))
    buf.write(b"WAVE")
    buf.write(b"fmt ")
    buf.write((16).to_bytes(4, "little"))  # Subchunk1Size
    buf.write((1).to_bytes(2, "little"))   # AudioFormat (PCM)
    buf.write((1).to_bytes(2, "little"))   # NumChannels
    buf.write((8000).to_bytes(4, "little"))# SampleRate
    buf.write((16000).to_bytes(4, "little"))# ByteRate
    buf.write((2).to_bytes(2, "little"))   # BlockAlign
    buf.write((16).to_bytes(2, "little"))  # BitsPerSample
    buf.write(b"data")
    buf.write((0).to_bytes(4, "little"))   # Subchunk2Size
    return buf.getvalue()


@pytest.mark.asyncio
async def test_cross_modal_contradiction_text_vs_image():
    # Message text claims Chase Bank, but Image analysis shows PayPal
    content_intel = ContentIntelligenceOutput(categories=["possible_impersonation"])
    impersonation = ImpersonationAnalysisOutput(
        claimed_organization="Chase",
        sender_domain_or_address="chase.com",
    )
    image_analysis = {
        "primary_organization": "PayPal",
        "visible_urls": ["https://paypal-update.org/login"],
    }
    extracted_urls = ["https://chase-security-verify.com/portal"]

    ev_output = await EvidenceAnalysisAgent.analyze(
        content_intel=content_intel,
        impersonation=impersonation,
        image_analysis=image_analysis,
        raw_text="Urgent notice from Chase Bank to update your card.",
        extracted_urls=extracted_urls,
    )

    assert isinstance(ev_output, EvidenceAnalysisOutput)
    # Check that cross-modal contradiction is detected
    assert any("Cross-Modal Contradiction" in c for c in ev_output.contradictions)
    assert any("Text vs Image" in c or "Conflicting" in c for c in ev_output.contradictions)


@pytest.mark.asyncio
async def test_cross_modal_contradiction_audio_vs_visual():
    # Audio claims authority from IRS / Police, but Image shows Amazon
    content_intel = ContentIntelligenceOutput(categories=["social_engineering"])
    image_analysis = {
        "primary_organization": "Amazon",
    }
    audio_analysis = {
        "claims_of_authority": ["Internal Revenue Service", "Federal Law Enforcement"],
        "full_transcript": "This is Officer Miller from the IRS. An arrest warrant has been issued.",
        "urgency_and_threats": ["Arrest warrant within 24 hours"],
    }

    ev_output = await EvidenceAnalysisAgent.analyze(
        content_intel=content_intel,
        image_analysis=image_analysis,
        audio_analysis=audio_analysis,
        raw_text="Customer notice attached.",
    )

    assert any("Cross-Modal Contradiction" in c for c in ev_output.contradictions)
    assert any("Audio vs Screenshot" in c or "Conflicting" in c for c in ev_output.contradictions)


@pytest.mark.asyncio
async def test_cross_modal_corroboration_multi_channel():
    # Both voice and text and image align on PayPal, while URL points to threat destination
    content_intel = ContentIntelligenceOutput(categories=["phishing_and_malicious_links"])
    impersonation = ImpersonationAnalysisOutput(claimed_organization="PayPal", is_domain_mismatch=True)
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["https://paypal.fake-account.xyz"],
        any_malicious_detected=True,
    )
    image_analysis = {
        "primary_organization": "PayPal",
    }
    audio_analysis = {
        "claims_of_authority": ["PayPal Security"],
        "full_transcript": "PayPal customer support: please verify your credentials.",
    }

    ev_output = await EvidenceAnalysisAgent.analyze(
        content_intel=content_intel,
        threat_intel=threat_intel,
        impersonation=impersonation,
        image_analysis=image_analysis,
        audio_analysis=audio_analysis,
        raw_text="PayPal security alert: verify your account.",
        extracted_urls=["https://paypal.fake-account.xyz"],
    )

    assert any("Cross-Modal Corroboration" in c for c in ev_output.corroborating_evidence)
    assert any("Multi-channel" in c or "Multiple modalities" in c for c in ev_output.corroborating_evidence)


@pytest.mark.asyncio
async def test_api_multimodal_text_and_url(client: AsyncClient):
    resp = await client.post(
        "/api/v1/investigations/multimodal",
        data={
            "text": "Please review this document immediately",
            "url": "https://www.wikipedia.org",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "multimodal"
    assert "url" in data["input_types"]
    assert "text" in data["input_types"]
    assert len(data["artifacts"]) >= 1


@pytest.mark.asyncio
async def test_api_multimodal_text_and_image(client: AsyncClient):
    png_bytes = create_test_image("PayPal")
    resp = await client.post(
        "/api/v1/investigations/multimodal",
        data={"text": "Received this suspicious payment screen"},
        files={"file": ("screenshot.png", png_bytes, "image/png")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "multimodal"
    assert "image" in data["input_types"]
    assert len(data["artifacts"]) >= 1


@pytest.mark.asyncio
async def test_api_multimodal_full_spectrum(client: AsyncClient):
    png_bytes = create_test_image("PayPal")
    wav_bytes = create_test_wav_audio()

    resp = await client.post(
        "/api/v1/investigations/multimodal",
        data={
            "text": "Urgent alert received via SMS with attached voicemail and receipt",
            "url": "https://www.google.com",
            "sender_hint": "Support Team",
        },
        files={
            "image_file": ("screenshot.png", png_bytes, "image/png"),
            "audio_file": ("voicemail.wav", wav_bytes, "audio/wav"),
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "multimodal"
    # Should include image, audio, url, text artifacts
    assert len(data["artifacts"]) >= 3
    assert data["status"] == "completed"
    assert "risk_assessment" in data


@pytest.mark.asyncio
async def test_api_multimodal_empty_rejection(client: AsyncClient):
    resp = await client.post("/api/v1/investigations/multimodal", data={})
    assert resp.status_code in (400, 422)
