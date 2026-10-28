"""TrustLens AI - Agent Structured Output Schemas

Pydantic models ensuring strict schema validation for specialized agent outputs.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.schemas.evidence import EvidenceItem


class EntityItem(BaseModel):
    type: str  # url, email, phone, organization, crypto_address, money
    value: str
    context: Optional[str] = None


class ClaimItem(BaseModel):
    claim_text: str
    context: Optional[str] = None


class ContentIntelligenceOutput(BaseModel):
    """Structured output from Agent A: Content Intelligence."""
    language: str = "en"
    categories: List[str] = Field(default_factory=list)
    entities: List[EntityItem] = Field(default_factory=list)
    claims: List[ClaimItem] = Field(default_factory=list)
    suspicious_phrases: List[str] = Field(default_factory=list)
    recommended_tools: List[str] = Field(default_factory=list)
    missing_information: List[str] = Field(default_factory=list)
    ambiguity_notes: Optional[str] = None


class ScamDetectionOutput(BaseModel):
    """Structured output from Agent B: Scam Detection."""
    urgency_detected: bool = False
    urgency_indicators: List[str] = Field(default_factory=list)
    credential_or_otp_harvesting: bool = False
    financial_demands: bool = False
    payment_instructions: List[str] = Field(default_factory=list)
    threat_or_reward_patterns: List[str] = Field(default_factory=list)
    social_engineering_tactics: List[str] = Field(default_factory=list)
    scam_likelihood: str = "low"  # low, medium, high
    observed_phrases: List[str] = Field(default_factory=list)
    reasoning: str = ""


class ImpersonationAnalysisOutput(BaseModel):
    """Structured output from Agent C: Impersonation Analysis."""
    claimed_organization: Optional[str] = None
    sender_domain_or_address: Optional[str] = None
    is_domain_mismatch: bool = False
    brand_spoofing_indicators: List[str] = Field(default_factory=list)
    inconsistencies: List[str] = Field(default_factory=list)
    official_domain_candidate: Optional[str] = None
    reasoning: str = ""


class ThreatIntelligenceOutput(BaseModel):
    """Structured output from Agent D: Threat Intelligence."""
    checked_urls: List[str] = Field(default_factory=list)
    records: List[EvidenceItem] = Field(default_factory=list)
    any_malicious_detected: bool = False
    phishing_detected: bool = False
    malware_detected: bool = False
    summary: str = ""


class ClaimVerificationOutput(BaseModel):
    """Structured output from Agent E: Claim Verification."""
    claims_analyzed: List[str] = Field(default_factory=list)
    debunked_claims_count: int = 0
    verified_true_count: int = 0
    unverified_claims_count: int = 0
    records: List[EvidenceItem] = Field(default_factory=list)
    summary: str = ""


class RiskSynthesisOutput(BaseModel):
    """Structured output from Agent F: Risk Synthesis."""
    agreement_observations: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    model_explanation: str = ""
    recommended_actions: List[str] = Field(default_factory=list)
