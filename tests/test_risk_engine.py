"""TrustLens AI - Deterministic Risk Engine Tests"""

from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.schemas.agent_outputs import (
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.services.risk_engine import DeterministicRiskEngine


def test_clean_content_scores_low():
    assessment = DeterministicRiskEngine.calculate_risk(
        evidence_records=[
            NormalizedEvidenceRecord(
                provider_name="VirusTotal",
                query_type="url",
                query_target="https://example.com",
                status=ProviderStatus.OK,
                is_malicious=False,
            )
        ]
    )
    assert assessment.risk_level == "low"
    assert assessment.risk_score < 30.0


def test_malicious_threat_intel_escalates_and_overrides():
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["http://malicious-site.xyz"],
        any_malicious_detected=True,
        malware_detected=True,
        summary="Verified malware payload host",
    )
    assessment = DeterministicRiskEngine.calculate_risk(threat_intel=threat_intel)
    assert assessment.risk_level in ("high", "critical")
    assert assessment.risk_score >= 55.0
    assert any("malware" in ind.lower() for ind in assessment.indicators)


def test_malicious_cannot_be_overridden_by_clean_record():
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["http://malicious-site.xyz"],
        phishing_detected=True,
        any_malicious_detected=True,
    )
    # Even if another provider claims clean, score must remain high/critical
    clean_ev = NormalizedEvidenceRecord(
        provider_name="CleanProvider",
        query_type="url",
        query_target="http://malicious-site.xyz",
        status=ProviderStatus.OK,
        is_malicious=False,
    )
    assessment = DeterministicRiskEngine.calculate_risk(
        threat_intel=threat_intel,
        evidence_records=[clean_ev],
    )
    assert assessment.risk_level in ("high", "critical")
    assert assessment.risk_score >= 70.0  # Rule: confirmed malicious floors at 70


def test_scam_credential_harvesting_detection():
    scam = ScamDetectionOutput(
        urgency_detected=True,
        urgency_indicators=["within 24 hours"],
        credential_or_otp_harvesting=True,
        financial_demands=True,
        scam_likelihood="high",
    )
    assessment = DeterministicRiskEngine.calculate_risk(scam_detection=scam)
    assert assessment.risk_level in ("high", "critical")
    assert any("credential" in ind.lower() for ind in assessment.indicators)


def test_contradiction_detection():
    clean_ev = NormalizedEvidenceRecord(
        provider_name="VirusTotal",
        query_type="url",
        query_target="http://fresh-phish-domain.xyz",
        status=ProviderStatus.OK,
        is_malicious=False,
    )
    scam = ScamDetectionOutput(
        credential_or_otp_harvesting=True,
        urgency_detected=True,
    )
    assessment = DeterministicRiskEngine.calculate_risk(
        scam_detection=scam,
        evidence_records=[clean_ev],
    )
    assert len(assessment.contradictions) > 0
    assert "VirusTotal" in assessment.contradictions[0]


def test_missing_provider_limitations_tracked():
    statuses = {
        "VirusTotal": ProviderStatus.NOT_CONFIGURED.value,
        "GoogleFactCheck": ProviderStatus.UNAVAILABLE.value,
    }
    assessment = DeterministicRiskEngine.calculate_risk(provider_statuses=statuses)
    assert len(assessment.limitations) == 2
    assert any("not configured" in lim.lower() for lim in assessment.limitations)
    assert any("unreachable" in lim.lower() for lim in assessment.limitations)
