# Changelog

All notable changes to TrustLens AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - Phase 3 Milestone: Real Audio & Voice-Note Investigation

### Added
- Dedicated audio investigation endpoint: `POST /api/v1/investigations/audio` supporting WAV, MP3, M4A, OGG, WebM, and AAC files.
- Audio magic-byte verification (`validate_audio_bytes`) enforcing container signatures, size limits, and format verification.
- Meta Muse Voice Transcribe client integration extracting complete speech transcripts, timestamps, and speaker segmentation.
- Meta Muse Spark structured audio reasoning (`AudioAnalysisSchema`) identifying financial demands, OTP/credential harvesting, urgency/coercion, claims of authority, wire/crypto transfer instructions, and claims requiring external verification.
- Auditable limitations and explicit disclaimers: no unverified speaker biometric identification or synthetic/cloned voice claims without dedicated acoustic models.
- Artifact persistence for audio files with SHA-256 integrity hashing and transcript synchronization in database.
- Comprehensive Phase 3 test suite (`tests/test_phase3_audio.py`) verifying magic bytes, corrupt/oversized file rejection, fallback analysis, and full end-to-end scam audio investigation.

### Changed
- Extended `InvestigationReportResponse` and `InvestigationState` with `transcription`, `audio_language`, `audio_duration_seconds`, and `transcription_segments`.
- Updated LangGraph state machine to preserve multimodal findings across agent classification nodes.

## [1.1.0] - Phase 2 Milestone: Multimodal Image & Screenshot Investigation

### Added
- Secure image upload endpoint: `POST /api/v1/investigations/image` accepting JPEG, PNG, and WebP formats.
- Magic-byte file signature validation and Pillow decompression bomb limits (`MAX_IMAGE_PIXELS = 100_000_000`, `MAX_IMAGE_WIDTH = 8192`, `MAX_IMAGE_HEIGHT = 8192`).
- Image metadata minimization (EXIF / GPS / device metadata stripping).
- Real Optical Character Recognition (OCR) engine via RapidOCR (PaddleOCR ONNX runtime) with line-level bounding boxes and confidence scores.
- Resilient OCR entity harvesting for URLs, emails, phone numbers, payment keywords, urgency warnings, organizations, and timestamps.
- Meta Muse Spark 1.3 multimodal visual reasoning integration (`analyze_image_structured`) using Pydantic structured output validation (`MetaVisionAnalysisSchema`).
- Image reconciliation engine (`ImageReconciler`) correlating OCR detections with Meta AI visual analysis, identifying corroborated URLs, discrepancies, ambiguous regions, and claims to verify without silently discarding conflicts.
- Comprehensive Phase 2 test suite (`tests/test_phase2_image.py`) covering valid/invalid image formats, oversized payloads, OCR extraction, reconciliation, prompt injection defense, and full end-to-end investigation pipeline.

### Changed
- Extended `InvestigationReportResponse` schema with `input_types`, `overall_risk`, `classification_labels`, `ocr_text`, `extraction_discrepancies`, `verified_claims`, `unverified_claims`, `recommended_actions`, `limitations`, and `analysis_timestamp`.
- Updated LangGraph state orchestrator to incorporate multimodal visual and OCR findings into content normalization and specialist routing.
- Enhanced deterministic risk engine to account for OCR extraction uncertainty and model-OCR discrepancy contradictions.

## [1.0.0] - Phase 1: Core Multimodal Agentic Safety Backend
- Initial release with text investigation, safe URL inspection, VirusTotal threat intelligence adapter, LangGraph agent orchestration, deterministic risk engine v1.2.0, and PostgreSQL/SQLite persistence.
