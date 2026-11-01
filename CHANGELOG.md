# Changelog

All notable changes to TrustLens AI will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
