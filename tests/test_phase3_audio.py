"""TrustLens AI - Phase 3 Audio and Voice-Note Investigation Tests

Tests real audio processing, validation, magic-byte inspection, transcription handling,
Muse Spark structured analysis, and end-to-end investigation workflows.
"""

from unittest.mock import AsyncMock, patch
import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from app.clients.meta_client import (
    MetaResponseMetadata,
    MetaTranscriptionResponse,
    TranscriptionSegment,
    meta_client,
)
from app.core.config import settings
from app.core.security import validate_audio_bytes
from app.main import app
from app.schemas.agent_outputs import AudioAnalysisSchema, EntityItem
from app.services.multimodal.audio_processor import AudioProcessor


# Valid test audio header generators
def make_dummy_wav() -> bytes:
    """Creates a minimal valid PCM WAV header (44 bytes)."""
    return (
        b"RIFF\x24\x00\x00\x00WAVE"
        b"fmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00"
        b"data\x00\x00\x00\x00"
    )


def make_dummy_mp3() -> bytes:
    """Creates a minimal valid MP3 frame with ID3v2 header."""
    return b"ID3\x03\x00\x00\x00\x00\x00\x00" + b"\xff\xfb\x90\x44" + b"\x00" * 32


def make_dummy_ogg() -> bytes:
    """Creates a minimal valid Ogg container header."""
    return b"OggS\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


def make_dummy_m4a() -> bytes:
    """Creates a minimal valid MP4/M4A ftyp header."""
    return b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00M4A mp42isom" + b"\x00" * 32


def make_dummy_webm() -> bytes:
    """Creates a minimal valid WebM EBML header."""
    return b"\x1a\x45\xdf\xa3\x01\x00\x00\x00\x00\x00\x00\x00" + b"\x00" * 32


def make_dummy_aac() -> bytes:
    """Creates a minimal valid AAC ADTS header."""
    return b"\xff\xf1\x50\x80\x00\x1f\xfc\x00\x00\x00\x00\x00"


# ============================================================================
# 1. Validation & Magic Byte Tests
# ============================================================================

def test_validate_audio_wav_success():
    data = make_dummy_wav()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "WAV"
    assert mime == "audio/wav"
    assert size == len(data)
    assert content == data


def test_validate_audio_mp3_success():
    data = make_dummy_mp3()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "MP3"
    assert mime == "audio/mpeg"


def test_validate_audio_ogg_success():
    data = make_dummy_ogg()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "OGG"
    assert mime == "audio/ogg"


def test_validate_audio_m4a_success():
    data = make_dummy_m4a()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "M4A"
    assert mime == "audio/mp4"


def test_validate_audio_webm_success():
    data = make_dummy_webm()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "WEBM"
    assert mime == "audio/webm"


def test_validate_audio_aac_success():
    data = make_dummy_aac()
    fmt, mime, size, content = validate_audio_bytes(data)
    assert fmt == "AAC"
    assert mime == "audio/aac"


def test_validate_audio_corrupt_rejected():
    with pytest.raises(HTTPException) as exc_info:
        validate_audio_bytes(b"TooSmall")
    assert exc_info.value.status_code == 415
    assert "too small" in exc_info.value.detail.lower()


def test_validate_audio_invalid_signature_rejected():
    # PNG bytes passed as audio
    fake_audio = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
    with pytest.raises(HTTPException) as exc_info:
        validate_audio_bytes(fake_audio)
    assert exc_info.value.status_code == 415
    assert "invalid audio signature" in exc_info.value.detail.lower()


def test_validate_audio_oversized_rejected():
    data = make_dummy_wav() + b"\x00" * 100
    with pytest.raises(HTTPException) as exc_info:
        validate_audio_bytes(data, max_size_bytes=50)
    assert exc_info.value.status_code in (413, 400)


def test_validate_audio_disallowed_type_rejected():
    data = make_dummy_wav()
    with pytest.raises(HTTPException) as exc_info:
        validate_audio_bytes(data, allowed_types=["audio/ogg"])
    assert exc_info.value.status_code == 415


# ============================================================================
# 2. AudioProcessor & Fallback Tests
# ============================================================================

def test_deterministic_audio_analysis_threat_detection():
    transcript = (
        "This is Agent Miller from the Federal Bureau of Investigation. "
        "Your account has been frozen and an arrest warrant has been issued. "
        "To clear this immediately, send 1500 dollars via wire transfer or visit "
        "https://fbi-settlement.fake/pay within 24 hours. Do not tell your bank teller. Call 800-555-0199."
    )
    analysis = AudioProcessor._deterministic_analysis_fallback(transcript)
    assert len(analysis.claims_of_authority) > 0
    assert len(analysis.urgency_and_threats) > 0
    assert len(analysis.requests_to_transfer_money) > 0
    assert len(analysis.suspicious_instructions) > 0
    assert len(analysis.potential_impersonation_indicators) > 0
    assert "https://fbi-settlement.fake/pay" in analysis.extracted_urls
    assert any("800-555-0199" in p for p in analysis.extracted_phone_numbers)
    assert len(analysis.transcription_limitations) == 3


@pytest.mark.asyncio
async def test_audio_processor_with_mocked_transcription():
    wav_bytes = make_dummy_wav()

    mock_resp = MetaTranscriptionResponse(
        text="Hello, this is Bank of America security. Please provide your one-time password code immediately.",
        language="en",
        duration_seconds=5.2,
        segments=[
            TranscriptionSegment(start=0.0, end=2.5, text="Hello, this is Bank of America security.", speaker="Speaker 1"),
            TranscriptionSegment(start=2.6, end=5.2, text="Please provide your one-time password code immediately.", speaker="Speaker 1"),
        ],
        metadata=MetaResponseMetadata(model_id="muse-voice-transcribe-1.0", latency_ms=120.0),
    )

    with patch.object(meta_client, "api_key", "test_key"):
        with patch.object(meta_client, "transcribe_audio", AsyncMock(return_value=mock_resp)):
            result = await AudioProcessor.process_audio(wav_bytes, filename="test.wav", mime_type="audio/wav")

            assert result.full_transcript == mock_resp.text
            assert result.language == "en"
            assert result.duration_seconds == 5.2
            assert len(result.segments) == 2
            assert result.analysis is not None
            assert len(result.analysis.otp_and_credential_requests) > 0
            assert len(result.analysis.urgency_and_threats) > 0


# ============================================================================
# 3. End-to-End API Investigation Tests
# ============================================================================

@pytest.mark.asyncio
async def test_api_audio_investigation_scam_call(client: AsyncClient):
    wav_bytes = make_dummy_wav()
    transcript_text = (
        "Internal Revenue Service notice. You have unpaid taxes of 450 dollars. "
        "Pay immediately at http://irs-tax-relief.fake or face police action within 24 hours."
    )

    mock_trans_resp = MetaTranscriptionResponse(
        text=transcript_text,
        language="en",
        duration_seconds=7.5,
        segments=[
            TranscriptionSegment(start=0.0, end=7.5, text=transcript_text, speaker="Speaker 1"),
        ],
        metadata=MetaResponseMetadata(model_id="muse-voice-transcribe-1.0", latency_ms=150.0),
    )

    with patch.object(meta_client, "api_key", "test_key"):
        with patch.object(meta_client, "transcribe_audio", AsyncMock(return_value=mock_trans_resp)):
            response = await client.post(
                f"{settings.API_V1_STR}/investigations/audio",
                files={"file": ("urgent_voicemail.wav", wav_bytes, "audio/wav")},
                data={"context_notes": "Voicemail left by unknown caller claiming to be tax office"},
            )

            assert response.status_code == 201
            body = response.json()
            assert body["input_type"] == "audio"
            assert body["transcription"] == transcript_text
            assert body["audio_language"] == "en"
            assert body["audio_duration_seconds"] == 7.5
            assert len(body["transcription_segments"]) == 1
            assert any("irs-tax-relief.fake" in u for u in body["extracted_urls"])
            assert any("tax" in ind.lower() or "authority" in ind.lower() or "urgency" in ind.lower() or "warrant" in ind.lower() for ind in body["observed_indicators"])
            assert body["final_risk_level"] in ("high", "critical", "medium")
            assert body["final_risk_score"] > 0.40

            # Check audio artifact in response
            audio_artifacts = [a for a in body["artifacts"] if a["artifact_type"] == "audio"]
            assert len(audio_artifacts) == 1
            assert audio_artifacts[0]["filename"] == "urgent_voicemail.wav"
            assert audio_artifacts[0]["mime_type"] == "audio/wav"
            assert audio_artifacts[0]["transcript_preview"] is not None

            # Check limitations disclaimers are present
            assert any("speaker identity" in lim.lower() for lim in body["limitations"])


@pytest.mark.asyncio
async def test_api_audio_investigation_benign_voicemail(client: AsyncClient):
    mp3_bytes = make_dummy_mp3()
    transcript_text = "Hi Mark, just calling to see if you are free for lunch tomorrow at 1 pm. Let me know!"

    mock_trans_resp = MetaTranscriptionResponse(
        text=transcript_text,
        language="en",
        duration_seconds=3.8,
        segments=[
            TranscriptionSegment(start=0.0, end=3.8, text=transcript_text, speaker="Speaker 1"),
        ],
        metadata=MetaResponseMetadata(model_id="muse-voice-transcribe-1.0", latency_ms=110.0),
    )

    with patch.object(meta_client, "api_key", "test_key"):
        with patch.object(meta_client, "transcribe_audio", AsyncMock(return_value=mock_trans_resp)):
            response = await client.post(
                f"{settings.API_V1_STR}/investigations/audio",
                files={"file": ("friendly_call.mp3", mp3_bytes, "audio/mpeg")},
                data={"context_notes": "Voicemail from a colleague"},
            )

            assert response.status_code == 201
            body = response.json()
            assert body["input_type"] == "audio"
            assert body["transcription"] == transcript_text
            assert body["final_risk_level"] in ("low", "minimal")
            assert body["final_risk_score"] <= 0.40


@pytest.mark.asyncio
async def test_api_audio_invalid_file_rejected(client: AsyncClient):
    response = await client.post(
        f"{settings.API_V1_STR}/investigations/audio",
        files={"file": ("fake_audio.wav", b"NotRealAudioContentAtAll", "audio/wav")},
    )
    assert response.status_code == 415
    assert "invalid audio signature" in response.json()["detail"].lower()

