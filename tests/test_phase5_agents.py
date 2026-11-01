"""TrustLens AI - Phase 5 Agentic Architecture Tests

Verifies all 7 specialized agents:
- Agent 1: Content Intelligence Agent
- Agent 2: Scam Detection Agent
- Agent 3: Impersonation Investigation Agent
- Agent 4: Threat Intelligence Agent
- Agent 5: Claim Verification Agent
- Agent 6: Evidence Analysis Agent
- Agent 7: Risk Synthesis Agent
Along with LangGraph checkpointed orchestration and state machine execution.
"""

import pytest
from app.agents.claim_verification import ClaimVerificationAgent
from app.agents.content_intelligence import ContentIntelligenceAgent
from app.agents.evidence_analysis import EvidenceAnalysisAgent
from app.agents.impersonation_analysis import ImpersonationAnalysisAgent
from app.agents.risk_synthesis import RiskSynthesisAgent
from app.agents.scam_detection import ScamDetectionAgent
from app.agents.threat_intelligence import ThreatIntelligenceAgent
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.orchestration.graph import execute_investigation_workflow
from app.orchestration.state import InvestigationState
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ContentIntelligenceOutput,
    EvidenceAnalysisOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)


@pytest.mark.asyncio
async def test_agent1_content_intelligence():
    text = "IRS alert: update your tax details immediately at https://irs-refund-claim.xyz or face penalties."
    output = await ContentIntelligenceAgent.analyze(text=text, sender_hint="IRS Support")
    assert isinstance(output, ContentIntelligenceOutput)
    assert any("irs-refund-claim.xyz" in e.value for e in output.entities)
    assert "threat_intel" in output.recommended_tools
    assert "impersonation_check" in output.recommended_tools


@pytest.mark.asyncio
async def test_agent2_scam_detection_urgency_and_otp():
    text = "URGENT: Your account will be locked in 15 minutes! Send the 6-digit OTP passcode to prevent arrest warrant."
    output = await ScamDetectionAgent.analyze(text)
    assert isinstance(output, ScamDetectionOutput)
    assert output.urgency_detected is True
    assert output.credential_or_otp_harvesting is True
    assert output.scam_likelihood == "high"


@pytest.mark.asyncio
async def test_agent3_impersonation_analysis_mismatch():
    text = "Dear Customer, PayPal has detected unauthorized activity. Verify at https://paypal.security-fix.ru"
    output = await ImpersonationAnalysisAgent.analyze(
        text=text,
        sender_hint="PayPal Security",
        extracted_urls=["https://paypal.security-fix.ru"],
    )
    assert isinstance(output, ImpersonationAnalysisOutput)
    assert output.is_domain_mismatch is True
    assert output.claimed_organization == "Paypal"
    assert output.official_domain_candidate == "paypal.com"
    assert len(output.inconsistencies) > 0


@pytest.mark.asyncio
async def test_agent4_threat_intelligence():
    urls = ["https://paypal.security-fix.ru"]
    threat_agent = ThreatIntelligenceAgent()
    output, records = await threat_agent.analyze(urls)
    assert isinstance(output, ThreatIntelligenceOutput)
    assert len(records) >= 1
    assert "domain_analysis" in output.model_dump()


@pytest.mark.asyncio
async def test_agent5_claim_verification():
    claims = ["Government executive order granting $5,000 cash subsidy or relief to all citizens."]
    claim_agent = ClaimVerificationAgent()
    output, records = await claim_agent.analyze(claims)
    assert isinstance(output, ClaimVerificationOutput)
    assert output.debunked_claims_count >= 1
    assert len(records) >= 1
    assert records[0].status == ProviderStatus.CONFIRMED_MATCH


@pytest.mark.asyncio
async def test_agent6_evidence_analysis_corroboration_and_contradictions():
    content_intel = ContentIntelligenceOutput(
        language="en",
        categories=["phishing_and_malicious_links", "social_engineering"],
        recommended_tools=["threat_intel", "scam_analysis", "impersonation_check"],
    )
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["https://chase-login-verify.top"],
        any_malicious_detected=True,
        provider_consensus="confirmed_phishing",
        provider_disagreements=["VirusTotal reported clean while PhishTank confirmed phishing"],
    )
    scam_detection = ScamDetectionOutput(
        urgency_detected=True,
        credential_or_otp_harvesting=True,
        scam_likelihood="high",
    )
    impersonation = ImpersonationAnalysisOutput(
        claimed_organization="Chase",
        is_domain_mismatch=True,
        inconsistencies=["Message claims Chase, URL is chase-login-verify.top"],
    )
    provider_statuses = {
        "VirusTotal": "ok",
        "PhishTank": "confirmed_match",
        "URLhaus": "not_configured",
    }

    ev_output = await EvidenceAnalysisAgent.analyze(
        content_intel=content_intel,
        threat_intel=threat_intel,
        scam_detection=scam_detection,
        impersonation=impersonation,
        provider_statuses=provider_statuses,
        planned_tools=["threat_intel", "scam_analysis", "impersonation_check"],
    )

    assert isinstance(ev_output, EvidenceAnalysisOutput)
    # Check corroboration
    assert len(ev_output.corroborating_evidence) >= 2
    # Check contradictions (domain mismatch + provider disagreement)
    assert any("Chase" in c for c in ev_output.contradictions)
    assert any("conflict" in c.lower() for c in ev_output.contradictions)
    # Check missing evidence
    assert any("URLhaus" in m for m in ev_output.missing_evidence)
    # Check coverage ratio (2 successful out of 3 = 0.67)
    assert 0.60 <= ev_output.evidence_coverage_ratio <= 0.70


@pytest.mark.asyncio
async def test_agent7_risk_synthesis_integration():
    content_intel = ContentIntelligenceOutput(categories=["financial_scams"])
    threat_intel = ThreatIntelligenceOutput(
        checked_urls=["https://phish.bad"],
        any_malicious_detected=True,
        provider_consensus="confirmed_phishing",
    )
    scam_detection = ScamDetectionOutput(credential_or_otp_harvesting=True, urgency_detected=True)
    evidence_analysis = EvidenceAnalysisOutput(
        corroborating_evidence=["Scam urgency corroborated with harvesting demand"],
        contradictions=["Claimed Bank A, domain Bank B"],
        missing_evidence=["Provider X unconfigured"],
        uncertainties=[],
        evidence_coverage_ratio=0.8,
    )

    synth_output, assessment = await RiskSynthesisAgent.synthesize(
        content_intel=content_intel,
        threat_intel=threat_intel,
        scam_detection=scam_detection,
        evidence_analysis=evidence_analysis,
    )

    assert assessment.risk_level in ("high", "critical")
    assert assessment.risk_score >= 60.0
    assert any("Claimed Bank A" in c for c in assessment.contradictions)
    assert any("Provider X" in m for m in assessment.limitations)
    assert len(assessment.recommendations) > 0


@pytest.mark.asyncio
async def test_full_7agent_langgraph_pipeline_execution():
    initial_state: InvestigationState = {
        "investigation_id": "test-phase5-7agents-001",
        "input_type": "text",
        "raw_text": "Federal Reserve: Claim your $5000 grant immediately at https://fed-grant-5000.xyz before deadline.",
        "sender_hint": "Federal Reserve Grants",
        "extracted_entities": [],
        "extracted_claims": [],
        "extracted_urls": [],
        "categories": [],
        "planned_tools": [],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(initial_state)

    assert final_state["status"] == "completed"
    findings = final_state["agent_findings"]
    # Verify all agent outputs are preserved in findings
    assert "content_intelligence" in findings
    assert "evidence_analysis" in findings
    assert "risk_synthesis" in findings
    assert "risk_assessment" in final_state
    assert final_state["final_risk_score"] > 50.0
    assert final_state["final_risk_level"] in ("high", "critical")
