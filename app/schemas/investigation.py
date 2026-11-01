"""TrustLens AI - Investigation Request and Response Schemas

Pydantic models for API request validation and structured investigation reports.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, HttpUrl
from app.schemas.evidence import EvidenceItem, ProviderStatusItem, RiskAssessmentSchema


class TextInvestigationRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=50000, description="The message, email, or suspicious text to analyze")
    sender_hint: Optional[str] = Field(None, max_length=255, description="Claimed sender name or email address")
    context_notes: Optional[str] = Field(None, max_length=2000, description="Optional context regarding how the message was received")


class URLInvestigationRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL or domain to inspect")
    context_notes: Optional[str] = Field(None, max_length=2000, description="Optional context")


class ClaimInvestigationRequest(BaseModel):
    claim_text: str = Field(..., min_length=5, max_length=10000, description="Public claim, policy statement, viral message, or announcement to verify")
    context_notes: Optional[str] = Field(None, max_length=2000, description="Optional context or origin of the claim")


class QuestionRequest(BaseModel):
    question: str = Field(..., min_length=2, max_length=1000, description="Question regarding the completed investigation findings")


class QuestionResponse(BaseModel):
    investigation_id: str
    question: str
    answer: str
    grounded_in_evidence: bool = True
    referenced_evidence_ids: List[str] = Field(default_factory=list)


class InvestigationStatusResponse(BaseModel):
    investigation_id: str
    status: str  # pending, in_progress, completed, failed
    input_type: str
    progress: int = 0
    created_at: datetime
    updated_at: Optional[datetime] = None
    error: Optional[str] = None


class InvestigationEvidenceResponse(BaseModel):
    investigation_id: str
    total_records: int
    providers_checked: List[ProviderStatusItem] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)


class ArtifactSummary(BaseModel):
    id: str
    artifact_type: str
    filename: Optional[str] = None
    mime_type: Optional[str] = None
    file_size: Optional[int] = None
    sha256_hash: Optional[str] = None
    ocr_preview: Optional[str] = None
    transcript_preview: Optional[str] = None


class ExtractedEntitySummary(BaseModel):
    entity_type: str
    value: str
    context: Optional[str] = None


class InvestigationReportResponse(BaseModel):
    investigation_id: str
    status: str
    input_type: str
    input_types: List[str] = Field(default_factory=list)
    overall_risk: str = "unknown"
    classification_labels: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    final_risk_level: str
    final_risk_score: float
    confidence: float
    summary: str
    ruleset_version: str
    model_id: Optional[str] = None
    created_at: datetime
    completed_at: Optional[datetime] = None
    analysis_timestamp: Optional[datetime] = None

    # Granular artifacts and evidence
    ocr_text: Optional[str] = None
    transcription: Optional[str] = None
    audio_language: Optional[str] = None
    audio_duration_seconds: Optional[float] = None
    transcription_segments: List[Dict[str, Any]] = Field(default_factory=list)
    extracted_urls: List[str] = Field(default_factory=list)
    observed_indicators: List[str] = Field(default_factory=list)
    extraction_discrepancies: List[str] = Field(default_factory=list)
    verified_claims: List[str] = Field(default_factory=list)
    unverified_claims: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)

    artifacts: List[ArtifactSummary] = Field(default_factory=list)
    extracted_entities: List[ExtractedEntitySummary] = Field(default_factory=list)
    extracted_claims: List[str] = Field(default_factory=list)
    provider_statuses: List[ProviderStatusItem] = Field(default_factory=list)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    evidence_sources: List[EvidenceItem] = Field(default_factory=list)
    agent_findings: Dict[str, Any] = Field(default_factory=dict)
    risk_assessment: Optional[RiskAssessmentSchema] = None


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ReadinessResponse(BaseModel):
    ready: bool
    database: str
    meta_model_api: Dict[str, Any]
    external_providers: Dict[str, bool]
