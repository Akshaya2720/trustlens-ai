"""TrustLens AI - LangGraph Investigation State

Defines the centralized state schema tracked throughout the investigation lifecycle.
"""

from typing import Any, Dict, List, Optional, TypedDict


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    input_type: str  # text, url, image, audio, multimodal
    raw_text: str
    sender_hint: Optional[str]
    context_notes: Optional[str]
    image_bytes: Optional[bytes]
    audio_bytes: Optional[bytes]
    filename: Optional[str]
    mime_type: Optional[str]

    ocr_text: Optional[str]
    ocr_confidence: Optional[float]
    is_ocr_uncertain: Optional[bool]
    transcription: Optional[str]
    audio_language: Optional[str]
    audio_duration_seconds: Optional[float]
    transcription_segments: List[Dict[str, Any]]
    extraction_discrepancies: List[str]
    verified_claims: List[str]
    unverified_claims: List[str]
    extracted_entities: List[Dict[str, Any]]
    extracted_claims: List[Dict[str, Any]]
    extracted_urls: List[str]
    categories: List[str]

    # Orchestrator Planning
    planned_tools: List[str]

    # Specialist Agent Outputs
    agent_findings: Dict[str, Any]
    evidence_analysis: Optional[Dict[str, Any]]
    external_evidence: List[Dict[str, Any]]
    provider_statuses: Dict[str, str]

    # Risk Assessment
    risk_assessment: Optional[Dict[str, Any]]
    final_risk_level: str
    final_risk_score: float
    confidence: float
    summary: str

    # Execution State
    status: str
    error: Optional[str]
