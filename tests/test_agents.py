"""TrustLens AI - Agent Unit Tests"""

import pytest
from app.agents.content_intelligence import ContentIntelligenceAgent
from app.agents.impersonation_analysis import ImpersonationAnalysisAgent
from app.agents.scam_detection import ScamDetectionAgent
from app.agents.threat_intelligence import ThreatIntelligenceAgent


@pytest.mark.asyncio
async def test_content_intelligence_deterministic_fallback():
    text = "Please send payment of $500 to https://fake-wire.com immediately or your account will be suspended."
    output = await ContentIntelligenceAgent.analyze(text=text)
    assert len(output.entities) >= 1
    assert "threat_intel" in output.recommended_tools
    assert "scam_analysis" in output.recommended_tools
    assert any("suspended" in p or "immediately" in p for p in output.suspicious_phrases)


@pytest.mark.asyncio
async def test_scam_detection_observable_features():
    text = "URGENT: Enter your one-time password (OTP) verification code now or face immediate arrest warrant."
    output = await ScamDetectionAgent.analyze(text=text)
    assert output.urgency_detected is True
    assert output.credential_or_otp_harvesting is True
    assert len(output.observed_phrases) > 0
    assert output.scam_likelihood == "high"


@pytest.mark.asyncio
async def test_impersonation_domain_mismatch_detected():
    text = "Security alert from PayPal: Please verify your billing details."
    urls = ["https://paypal-update-account.biz/login"]
    output = await ImpersonationAnalysisAgent.analyze(text=text, extracted_urls=urls)
    assert output.claimed_organization == "Paypal"
    assert output.is_domain_mismatch is True
    assert len(output.inconsistencies) > 0
    assert "paypal-update-account.biz" in output.inconsistencies[0]


@pytest.mark.asyncio
async def test_threat_intelligence_empty_urls():
    agent = ThreatIntelligenceAgent()
    output, records = await agent.analyze(urls=[])
    assert len(output.checked_urls) == 0
    assert output.any_malicious_detected is False
