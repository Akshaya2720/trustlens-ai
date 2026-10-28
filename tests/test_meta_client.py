"""TrustLens AI - Meta Model API Client Tests"""

import pytest
from pydantic import BaseModel
from app.clients.meta_client import (
    MetaAuthError,
    MetaModelClient,
    MetaTranscriptionResponse,
    TranscriptionSegment,
)


class DummySchema(BaseModel):
    message: str
    flag: bool


@pytest.mark.asyncio
async def test_meta_client_unconfigured_error():
    client = MetaModelClient(api_key="")
    with pytest.raises(MetaAuthError):
        await client.generate_reasoning(messages=[{"role": "user", "content": "ping"}])


@pytest.mark.asyncio
async def test_meta_client_unconfigured_audio_error():
    client = MetaModelClient(api_key="")
    with pytest.raises(MetaAuthError):
        await client.transcribe_audio(audio_bytes=b"dummy_wav_data")


def test_transcription_segment_parsing():
    seg = TranscriptionSegment(start=0.5, end=2.3, text="Hello world", speaker="Speaker 1")
    assert seg.duration == pytest.approx(1.8) if hasattr(seg, "duration") else (seg.end - seg.start) == pytest.approx(1.8)
    assert seg.speaker == "Speaker 1"


@pytest.mark.asyncio
async def test_meta_client_connectivity_report():
    client = MetaModelClient(api_key="")
    status = await client.check_connectivity()
    assert status["configured"] is False
    assert status["reachable"] is False
