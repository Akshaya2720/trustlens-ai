"""TrustLens AI - Multimodal Audio & Voice Note Processor

Handles audio uploads using Meta's Muse Voice Transcribe model.
Extracts transcription, segment timestamps, and speaker turns.
"""

from typing import List, Optional
from pydantic import BaseModel
from app.clients.meta_client import meta_client
from app.core.config import settings
from app.core.logging import logger
from app.core.security import compute_sha256


class AudioSegmentItem(BaseModel):
    start: float
    end: float
    text: str
    speaker: Optional[str] = None


class AudioTranscriptionResult(BaseModel):
    sha256: str
    filename: str
    mime_type: str
    file_size: int
    duration_seconds: Optional[float] = None
    language: Optional[str] = None
    full_transcript: str
    segments: List[AudioSegmentItem] = []
    error_message: Optional[str] = None


class AudioProcessor:
    """Processes audio and voice notes for TrustLens AI."""

    @classmethod
    async def process_audio(
        cls, audio_bytes: bytes, filename: str = "voice_note.mp3", mime_type: str = "audio/mpeg"
    ) -> AudioTranscriptionResult:
        """Transcribes audio using Muse Voice Transcribe."""
        sha256 = compute_sha256(audio_bytes)
        file_size = len(audio_bytes)

        if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
            raise ValueError(f"Audio file size ({file_size} bytes) exceeds limit ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)")

        if not meta_client.is_configured:
            return AudioTranscriptionResult(
                sha256=sha256,
                filename=filename,
                mime_type=mime_type,
                file_size=file_size,
                full_transcript="",
                error_message="Muse Voice Transcribe unavailable: MODEL_API_KEY is not configured.",
            )

        try:
            trans_resp = await meta_client.transcribe_audio(
                audio_bytes=audio_bytes,
                filename=filename,
                mime_type=mime_type,
            )

            segments = [
                AudioSegmentItem(start=s.start, end=s.end, text=s.text, speaker=s.speaker)
                for s in trans_resp.segments
            ]

            return AudioTranscriptionResult(
                sha256=sha256,
                filename=filename,
                mime_type=mime_type,
                file_size=file_size,
                duration_seconds=trans_resp.duration_seconds,
                language=trans_resp.language,
                full_transcript=trans_resp.text,
                segments=segments,
            )

        except Exception as e:
            logger.warning(f"Audio transcription error: {e}")
            return AudioTranscriptionResult(
                sha256=sha256,
                filename=filename,
                mime_type=mime_type,
                file_size=file_size,
                full_transcript="",
                error_message=f"Audio transcription failed: {str(e)}",
            )
