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
    provider_consensus: str = "clean"  # confirmed_malware, confirmed_phishing, malicious, disagreement, clean, unknown
    provider_disagreements: List[str] = Field(default_factory=list)
    domain_analysis: Dict[str, Any] = Field(default_factory=dict)
    redirect_analysis: Dict[str, Any] = Field(default_factory=dict)
    summary: str = ""


class ClaimVerificationOutput(BaseModel):
    """Structured output from Agent E: Claim Verification."""
    claims_analyzed: List[str] = Field(default_factory=list)
    debunked_claims_count: int = 0
    verified_true_count: int = 0
    unverified_claims_count: int = 0
    records: List[EvidenceItem] = Field(default_factory=list)
    summary: str = ""


class EvidenceAnalysisOutput(BaseModel):
    """Structured output from Agent 6: Evidence Analysis."""
    corroborating_evidence: List[str] = Field(default_factory=list, description="Cross-modal or multi-agent corroborated evidence findings")
    contradictions: List[str] = Field(default_factory=list, description="Direct contradictions or inconsistencies across findings")
    missing_evidence: List[str] = Field(default_factory=list, description="Expected security evidence or data sources that are absent or unavailable")
    uncertainties: List[str] = Field(default_factory=list, description="Low-confidence, ambiguous, or unverifiable claims/artifacts")
    evidence_coverage_ratio: float = Field(default=1.0, ge=0.0, le=1.0, description="Proportion of scheduled security checks successfully completed")
    summary: str = Field(default="", description="Objective synthesis of evidence reconciliation")


class RiskSynthesisOutput(BaseModel):
    """Structured output from Agent F: Risk Synthesis."""
    agreement_observations: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    model_explanation: str = ""
    recommended_actions: List[str] = Field(default_factory=list)


class MetaVisionAnalysisSchema(BaseModel):
    """Structured output from Meta Multimodal Vision model (Muse Spark 1.3)."""
    apparent_purpose: str = Field(..., description="Apparent purpose or topic of the message or screenshot")
    visible_elements: List[str] = Field(default_factory=list, description="Visibly present UI elements, headers, logos, or raw text directly observed")
    inferred_context: List[str] = Field(default_factory=list, description="Contextual inferences made by the model, clearly separated from visual observations")
    suspicious_instructions: List[str] = Field(default_factory=list, description="Suspicious instructions, urgency triggers, or calls to action")
    claimed_sender_or_organization: Optional[str] = Field(None, description="Organization, brand, or entity claimed or depicted in the image")
    visible_urls: List[str] = Field(default_factory=list, description="URLs or domain names visibly displayed in the image")
    payment_or_credential_requests: List[str] = Field(default_factory=list, description="Explicit requests for credentials, passwords, OTPs, wire transfers, or crypto")
    impersonation_indicators: List[str] = Field(default_factory=list, description="Visual indicators suggestive of impersonation or UI spoofing")
    claims_requiring_verification: List[str] = Field(default_factory=list, description="Factual claims (e.g. government notice, fine, prize, legal threat) that require external verification")
    ambiguities_and_limitations: List[str] = Field(default_factory=list, description="Unclear or low-resolution elements, cropped context, or uncertainty")
    raw_summary: str = Field(..., description="Factual, non-speculative summary of observable visual elements")


class OCRExtractionResult(BaseModel):
    """Structured output from OCR extraction engine (RapidOCR / Tesseract)."""
    raw_text: str = ""
    confidence: float = 0.0  # 0.0 to 1.0 (mean word/line confidence)
    min_confidence: float = 0.0
    word_count: int = 0
    lines: List[Dict[str, Any]] = Field(default_factory=list)
    detected_urls: List[str] = Field(default_factory=list)
    detected_emails: List[str] = Field(default_factory=list)
    detected_phones: List[str] = Field(default_factory=list)
    detected_payment_terms: List[str] = Field(default_factory=list)
    detected_warnings: List[str] = Field(default_factory=list)
    claimed_organizations: List[str] = Field(default_factory=list)
    detected_timestamps: List[str] = Field(default_factory=list)
    is_low_confidence: bool = False
    engine_used: str = "none"
    engine_status: str = "ok"  # "ok", "low_confidence", "empty", "error", "unavailable"


class ReconciledImageAnalysis(BaseModel):
    """Reconciles OCR extraction with Meta AI multimodal vision analysis."""
    all_urls: List[str] = Field(default_factory=list)
    urls_corroborated: List[str] = Field(default_factory=list)
    urls_ocr_only: List[str] = Field(default_factory=list)
    urls_meta_only: List[str] = Field(default_factory=list)
    discrepancies: List[str] = Field(default_factory=list)
    ambiguous_regions: List[str] = Field(default_factory=list)
    claims_to_verify: List[str] = Field(default_factory=list)
    primary_organization: Optional[str] = None
    organization_source: str = "none"  # "both", "ocr", "meta", "none"
    reconciled_text: str = ""
    ocr_confidence: Optional[float] = None
    is_ocr_uncertain: bool = False
    image_sha256: str = ""
    reconciliation_notes: List[str] = Field(default_factory=list)


class AudioAnalysisSchema(BaseModel):
    """Structured output from Meta Muse Spark analyzing voice notes and transcripts."""
    apparent_topic: str = Field(..., description="Apparent topic, premise, or scenario presented in the audio")
    financial_requests: List[str] = Field(default_factory=list, description="Any financial requests, demands, fees, or account inquiries")
    otp_and_credential_requests: List[str] = Field(default_factory=list, description="Explicit requests for OTPs, passwords, PINs, or credentials")
    urgency_and_threats: List[str] = Field(default_factory=list, description="High-pressure tactics, artificial deadlines, legal threats, arrest claims")
    claims_of_authority: List[str] = Field(default_factory=list, description="Claims to represent government agencies, law enforcement, executive leadership, or banks")
    requests_to_transfer_money: List[str] = Field(default_factory=list, description="Direct requests to send funds, gift cards, crypto, or wire transfers")
    suspicious_instructions: List[str] = Field(default_factory=list, description="Commands to install remote software, keep secrets, or avoid speaking to branch staff")
    potential_impersonation_indicators: List[str] = Field(default_factory=list, description="Indicators suggestive of identity or authority impersonation")
    claims_requiring_verification: List[str] = Field(default_factory=list, description="Factual claims that require external verification")
    extracted_urls: List[str] = Field(default_factory=list, description="URLs or domain names spoken or referenced in the audio")
    extracted_phone_numbers: List[str] = Field(default_factory=list, description="Phone numbers spoken or referenced in the audio")
    extracted_entities: List[EntityItem] = Field(default_factory=list, description="Structured entities mentioned in the audio")
    transcription_limitations: List[str] = Field(
        default_factory=lambda: [
            "Audio transcription confidence depends on acoustic clarity and background noise.",
            "Speaker identity cannot be verified or authenticated from a voice recording alone.",
            "AI-generated or cloned voice detection requires a separately validated acoustic model.",
        ],
        description="Explicit acoustic and identification boundaries",
    )
    analysis_summary: str = Field(..., description="Objective, non-speculative factual summary of the audio content")

