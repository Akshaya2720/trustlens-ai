"""TrustLens AI - Multimodal Audio & Voice Note Processor

Handles audio uploads using Meta's Muse Voice Transcribe model and Muse Spark 1.3 reasoning.
Extracts transcription, segment timestamps, speaker turns, URLs, financial requests,
and suspicious social engineering cues with auditable limitations.
"""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.clients.meta_client import meta_client
from app.core.config import settings
from app.core.logging import logger
from app.core.security import compute_sha256, isolate_untrusted_input
from app.schemas.agent_outputs import AudioAnalysisSchema, EntityItem
from app.services.content_normalizer import ContentNormalizer
from app.services.safe_url import SafeURLInspector


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
    segments: List[AudioSegmentItem] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_phone_numbers: List[str] = Field(default_factory=list)
    extracted_entities: List[Dict[str, Any]] = Field(default_factory=list)
    extracted_claims: List[Dict[str, Any]] = Field(default_factory=list)
    suspicious_indicators: List[str] = Field(default_factory=list)
    transcription_limitations: List[str] = Field(default_factory=list)
    analysis: Optional[AudioAnalysisSchema] = None
    error_message: Optional[str] = None


DEFAULT_AUDIO_LIMITATIONS = [
    "Audio transcription accuracy is subject to acoustic clarity, compression artifacts, and background noise.",
    "Speaker identity cannot be definitively authenticated or verified solely from a voice recording.",
    "Detection of AI-generated synthetic or cloned voice notes requires a separately calibrated acoustic detection model.",
]

PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
)


class AudioProcessor:
    """Processes audio and voice notes for TrustLens AI."""

    @classmethod
    def _deterministic_analysis_fallback(
        cls, transcript: str, context_notes: Optional[str] = None
    ) -> AudioAnalysisSchema:
        """Deterministic keyword and regex-based analysis fallback when Meta API is unavailable."""
        lower_text = transcript.lower()

        financial_requests = []
        otp_requests = []
        urgency_threats = []
        authority_claims = []
        transfer_requests = []
        suspicious_instructions = []
        impersonation_indicators = []
        claims_to_verify = []

        if any(w in lower_text for w in ["fee", "payment", "dollars", "usd", "$", "balance", "cost"]):
            financial_requests.append("Mention of financial fees, balance, or payments in transcript")

        if any(w in lower_text for w in ["otp", "one-time password", "verification code", "pin", "password"]):
            otp_requests.append("Audio requests or references a one-time verification code or password")

        if any(w in lower_text for w in ["immediately", "urgent", "24 hours", "arrest", "warrant", "suspend", "frozen"]):
            urgency_threats.append("Urgent deadline or coercion language detected in speech")

        if any(w in lower_text for w in ["fbi", "police", "irs", "customs", "central bank", "fraud department", "security team"]):
            authority_claims.append("Speaker claims to represent law enforcement, government agency, or bank security")

        if any(w in lower_text for w in ["wire", "gift card", "crypto", "bitcoin", "western union", "transfer"]):
            transfer_requests.append("Instructions to transfer funds, purchase gift cards, or send cryptocurrency")

        if any(w in lower_text for w in ["do not tell", "stay on the line", "install anydesk", "teamviewer", "keep this secret"]):
            suspicious_instructions.append("Instruction to maintain secrecy or install remote desktop software")

        if authority_claims and transfer_requests:
            impersonation_indicators.append("Classic social-engineering pattern: authority claim paired with direct payment instruction")

        # Claims to verify
        for s in transcript.split("."):
            s_clean = s.strip()
            if any(w in s_clean.lower() for w in ["account has been", "package is held", "warrant has been issued", "tax refund"]):
                claims_to_verify.append(s_clean)

        # URLs
        urls = []
        for m in ContentNormalizer.URL_PATTERN.finditer(transcript):
            u = SafeURLInspector.normalize_url(m.group(0))
            if u not in urls:
                urls.append(u)

        # Phone numbers
        phones = list(set(PHONE_PATTERN.findall(transcript)))

        entities = [
            EntityItem(type="url", value=u) for u in urls
        ] + [
            EntityItem(type="phone", value=p) for p in phones
        ]

        summary = f"Spoken audio contains {len(transcript.split())} words."
        if urgency_threats or transfer_requests or otp_requests:
            summary += f" Suspicious indicators observed: {len(urgency_threats + transfer_requests + otp_requests)} risk patterns."

        return AudioAnalysisSchema(
            apparent_topic="Voice communication" if not authority_claims else f"Authority notification ({', '.join(authority_claims)})",
            financial_requests=financial_requests,
            otp_and_credential_requests=otp_requests,
            urgency_and_threats=urgency_threats,
            claims_of_authority=authority_claims,
            requests_to_transfer_money=transfer_requests,
            suspicious_instructions=suspicious_instructions,
            potential_impersonation_indicators=impersonation_indicators,
            claims_requiring_verification=claims_to_verify,
            extracted_urls=urls,
            extracted_phone_numbers=phones,
            extracted_entities=entities,
            transcription_limitations=DEFAULT_AUDIO_LIMITATIONS,
            analysis_summary=summary,
        )

    @classmethod
    async def analyze_transcript_structured(
        cls,
        transcript: str,
        context_notes: Optional[str] = None,
    ) -> Optional[AudioAnalysisSchema]:
        """Runs Meta Muse Spark structured reasoning on transcribed audio."""
        if not transcript or not meta_client.is_configured:
            return None

        prompt = (
            "You are a Senior Threat Intelligence Investigator examining an untrusted audio transcript for fraud, "
            "scam patterns, impersonation, credential harvesting, or coercion.\n\n"
            "Analyze the transcript and produce structured findings according to the schema:\n"
            "- Identify any financial demands, wire transfers, crypto requests, or fee payments.\n"
            "- Identify OTP, password, or verification code requests.\n"
            "- Identify urgency, threats, or claims of legal/regulatory authority.\n"
            "- Identify potential impersonation of banks, tech companies, or law enforcement.\n"
            "- Identify claims that require external factual verification.\n"
            "- Identify any URLs or phone numbers referenced.\n"
            "- Distinguish what was spoken in the audio from external inferences.\n"
            "- CRITICAL: Do NOT claim that the speaker's identity is verified from the voice note.\n"
            "- CRITICAL: Do NOT claim to detect AI-generated or cloned voice without a dedicated biometric acoustic model.\n\n"
            f"Context Notes: {context_notes or 'None'}\n"
            f"Transcript:\n{isolate_untrusted_input(transcript, 'AUDIO_TRANSCRIPT')}"
        )

        try:
            analysis, _ = await meta_client.generate_structured(
                messages=[{"role": "user", "content": prompt}],
                schema=AudioAnalysisSchema,
                temperature=0.1,
            )
            return analysis
        except Exception as e:
            logger.warning(f"Failed structured audio analysis with Muse Spark: {e}")
            return None

    @classmethod
    async def process_audio(
        cls,
        audio_bytes: bytes,
        filename: str = "voice_note.mp3",
        mime_type: str = "audio/mpeg",
        context_notes: Optional[str] = None,
    ) -> AudioTranscriptionResult:
        """Transcribes audio using Muse Voice Transcribe and analyzes with Muse Spark."""
        sha256 = compute_sha256(audio_bytes)
        file_size = len(audio_bytes)

        if file_size > settings.MAX_UPLOAD_SIZE_BYTES:
            raise ValueError(f"Audio file size ({file_size} bytes) exceeds limit ({settings.MAX_UPLOAD_SIZE_BYTES} bytes)")

        full_transcript = ""
        duration_seconds = None
        language = None
        segments: List[AudioSegmentItem] = []
        error_msg = None

        if meta_client.is_configured:
            try:
                trans_resp = await meta_client.transcribe_audio(
                    audio_bytes=audio_bytes,
                    filename=filename,
                    mime_type=mime_type,
                )
                full_transcript = trans_resp.text
                duration_seconds = trans_resp.duration_seconds
                language = trans_resp.language
                segments = [
                    AudioSegmentItem(start=s.start, end=s.end, text=s.text, speaker=s.speaker)
                    for s in trans_resp.segments
                ]
            except Exception as e:
                logger.warning(f"Meta Voice Transcribe error: {e}")
                error_msg = f"Muse Voice Transcribe error: {str(e)}"
        else:
            error_msg = "Muse Voice Transcribe unavailable: MODEL_API_KEY is not configured."

        # If transcript is empty (due to lack of API key or silent audio), check if context or fallback provides any text
        structured_analysis: Optional[AudioAnalysisSchema] = None
        if full_transcript:
            structured_analysis = await cls.analyze_transcript_structured(full_transcript, context_notes)
            if not structured_analysis:
                structured_analysis = cls._deterministic_analysis_fallback(full_transcript, context_notes)
        elif context_notes and not full_transcript:
            structured_analysis = cls._deterministic_analysis_fallback(f"Context: {context_notes}", context_notes)

        # Aggregate URLs, entities, and claims
        extracted_urls: List[str] = []
        extracted_phones: List[str] = []
        extracted_entities: List[Dict[str, Any]] = []
        extracted_claims: List[Dict[str, Any]] = []
        indicators: List[str] = []

        if structured_analysis:
            extracted_urls.extend(structured_analysis.extracted_urls)
            extracted_phones.extend(structured_analysis.extracted_phone_numbers)
            for ent in structured_analysis.extracted_entities:
                extracted_entities.append({"type": ent.type, "value": ent.value, "context": ent.context})
            for clm in structured_analysis.claims_requiring_verification:
                extracted_claims.append({"claim_text": clm, "context": "Audio transcript statement"})

            # Indicators
            indicators.extend(structured_analysis.urgency_and_threats)
            indicators.extend(structured_analysis.financial_requests)
            indicators.extend(structured_analysis.otp_and_credential_requests)
            indicators.extend(structured_analysis.requests_to_transfer_money)
            indicators.extend(structured_analysis.suspicious_instructions)
            indicators.extend(structured_analysis.potential_impersonation_indicators)

        # Also extract deterministic entities from transcript
        if full_transcript:
            for ent in ContentNormalizer.extract_entities(full_transcript):
                if ent["value"] not in [e.get("value") for e in extracted_entities]:
                    extracted_entities.append(ent)
                if ent["type"] == "url" and ent["value"] not in extracted_urls:
                    extracted_urls.append(ent["value"])

        return AudioTranscriptionResult(
            sha256=sha256,
            filename=filename,
            mime_type=mime_type,
            file_size=file_size,
            duration_seconds=duration_seconds,
            language=language,
            full_transcript=full_transcript,
            segments=segments,
            extracted_urls=extracted_urls,
            extracted_phone_numbers=extracted_phones,
            extracted_entities=extracted_entities,
            extracted_claims=extracted_claims,
            suspicious_indicators=indicators,
            transcription_limitations=DEFAULT_AUDIO_LIMITATIONS,
            analysis=structured_analysis,
            error_message=error_msg,
        )
