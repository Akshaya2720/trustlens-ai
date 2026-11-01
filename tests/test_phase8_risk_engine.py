"""TrustLens AI - Phase 8 Advanced Deterministic Risk Engine Tests

Verifies the mathematical rigor, transparent floor logic, contradiction penalties,
confidence decay, and strict non-hallucination guarantees of DeterministicRiskEngine:
- Zero model hallucination in risk scoring (rules calculate score, not LLM)
- Enforcing floor rules:
  * Confirmed malware/phishing >= 70.0 (High/Critical)
  * Debunked claim >= 65.0 (High/Critical)
  * Credential harvesting + Urgency >= 60.0 (High)
  * Cross-modal contradiction >= 65.0 (High)
- Contradiction escalation weights (+25.0 to +30.0)
- Confidence calculation: calibrated strictly based on evidence coverage and data quality
- Classification boundaries: Low (<30), Medium (30-59), High (60-84), Critical (85-100), Unknown
- Unverified URL safety policy: unverified URL cannot be classified as low risk (safe)
"""

import pytest
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.services.risk_engine import DeterministicRiskEngine


def test_risk_engine_deterministic_reproducibility():
    # Calling calculate_risk twice with identical inputs must return bitwise identical scores
    scam = ScamDetectionOutput(credential_or_otp_harvesting=True, urgency_detected=True)
    res1 = DeterministicRiskEngine.calculate_risk(scam_detection=scam)
    res2 = DeterministicRiskEngine.calculate_risk(scam_detection=scam)
    assert res1.risk_score == res2.risk_score
    assert res1.risk_level == res2.risk_level
    assert res1.confidence == res2.confidence


def test_risk_engine_floor_confirmed_malicious():
    # Any confirmed malicious threat record must force score to at least 70.0 (High)
    threat = ThreatIntelligenceOutput(
        malware_detected=True,
        any_malicious_detected=True,
    )
    res = DeterministicRiskEngine.calculate_risk(threat_intel=threat)
    assert res.risk_score >= 70.0
    assert res.risk_level in ("high", "critical")


def test_risk_engine_floor_debunked_claim():
    # Debunked false claim must force score to at least 65.0 (High)
    claims = ClaimVerificationOutput(debunked_claims_count=1)
    res = DeterministicRiskEngine.calculate_risk(claim_verification=claims)
    assert res.risk_score >= 65.0
    assert res.risk_level in ("high", "critical")


def test_risk_engine_floor_harvesting_plus_urgency():
    # OTP harvesting + urgency must force score to at least 60.0 (High)
    scam = ScamDetectionOutput(
        credential_or_otp_harvesting=True,
        urgency_detected=True,
    )
    res = DeterministicRiskEngine.calculate_risk(scam_detection=scam)
    assert res.risk_score >= 60.0
    assert res.risk_level in ("high", "critical")


def test_risk_engine_floor_cross_modal_contradiction():
    # Cross-modal contradiction must force score to at least 65.0 (High)
    discrepancies = ["Cross-Modal Contradiction: Voice claims IRS while screenshot shows Amazon"]
    res = DeterministicRiskEngine.calculate_risk(discrepancies=discrepancies)
    assert res.risk_score >= 65.0
    assert res.risk_level in ("high", "critical")
    assert any("Cross-Modal" in ind for ind in res.indicators)


def test_risk_engine_unverified_url_safety_policy():
    # An unverified URL with unconfigured or missing provider records must NEVER be classified as low risk
    evidence = [
        NormalizedEvidenceRecord(
            provider_name="VirusTotal",
            query_type="url",
            query_target="https://unknown-suspicious.biz",
            status=ProviderStatus.NOT_CONFIGURED,
        )
    ]
    res = DeterministicRiskEngine.calculate_risk(evidence_records=evidence)
    # Must be "unknown", never "low"
    assert res.risk_level == "unknown"
    assert any("URL reputation could not be verified" in lim for lim in res.limitations)


def test_risk_engine_verified_authentic_discount():
    # Verified true public claim discounts risk
    claims = ClaimVerificationOutput(verified_true_count=1)
    res = DeterministicRiskEngine.calculate_risk(claim_verification=claims)
    assert res.risk_score == 0.0
    assert res.risk_level == "low"
    assert any("Verified authentic" in ind for ind in res.indicators)


def test_risk_engine_confidence_decay_on_uncertainty():
    # Low OCR confidence decays confidence
    scam = ScamDetectionOutput(urgency_detected=True)
    res_clean = DeterministicRiskEngine.calculate_risk(scam_detection=scam, ocr_confidence=0.95)
    res_uncertain = DeterministicRiskEngine.calculate_risk(
        scam_detection=scam,
        ocr_confidence=0.35,
        is_ocr_uncertain=True,
    )
    assert res_uncertain.confidence < res_clean.confidence
