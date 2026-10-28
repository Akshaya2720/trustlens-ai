"""TrustLens AI - Evidence and Risk Schemas

Pydantic schemas for external evidence, provider statuses, and risk calculations.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProviderStatusItem(BaseModel):
    provider_name: str
    status: str
    latency_ms: float = 0.0
    checked_at: Optional[datetime] = None


class EvidenceItem(BaseModel):
    id: Optional[str] = None
    provider_name: str
    query_type: str
    query_target: str
    raw_status: str
    is_malicious: Optional[bool] = None
    threat_description: Optional[str] = None
    source_reference: Optional[str] = None
    normalized_result: Dict[str, Any] = Field(default_factory=dict)
    retrieved_at: Optional[datetime] = None
    latency_ms: float = 0.0
    error_message: Optional[str] = None


class RiskAssessmentSchema(BaseModel):
    risk_level: str  # low, medium, high, critical, unknown
    risk_score: float = Field(ge=0.0, le=100.0)
    confidence: float = Field(ge=0.0, le=1.0)
    indicators: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    generated_at: Optional[datetime] = None
