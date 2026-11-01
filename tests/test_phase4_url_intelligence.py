"""TrustLens AI - Phase 4 Advanced URL and Domain Intelligence Tests

Verifies:
1. Safe URL normalization and non-http/https rejection.
2. Strict SSRF, private IP, and cloud metadata rejection.
3. Deep domain and subdomain analysis (subdomain brand spoofing, raw IP, punycode, high-risk TLDs).
4. Restricted redirect-chain analysis with per-hop SSRF validation.
5. Multi-provider threat intelligence (VirusTotal, URLhaus, PhishTank).
6. Provider disagreement tracking and reporting.
7. Risk engine policy: unverified/unknown URLs never classified as safe.
8. End-to-end POST /api/v1/investigations/url endpoint execution and persistence.
"""

from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.config import settings
from app.schemas.agent_outputs import ThreatIntelligenceOutput
from app.services.risk_engine import DeterministicRiskEngine
from app.services.safe_url import SafeURLInspector


# ============================================================================
# 1. URL Normalization & Scheme Validation Tests
# ============================================================================

def test_url_normalization():
    assert SafeURLInspector.normalize_url("paypal.com/login") == "http://paypal.com/login"
    assert SafeURLInspector.normalize_url("https://secure.example.com") == "https://secure.example.com/"
    assert SafeURLInspector.normalize_url("http://EXAMPLE.COM/PATH?q=1") == "http://example.com/PATH?q=1"


def test_unsupported_schemes_rejected():
    dangerous_urls = [
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html;base64,PHNjcmlwdD4=",
        "ftp://ftp.example.com/pub",
        "gopher://gopher.example.com",
    ]
    for bad_url in dangerous_urls:
        val = SafeURLInspector.validate_url(bad_url)
        assert not val.is_safe
        assert "scheme" in (val.reason or "").lower()


# ============================================================================
# 2. SSRF & Private IP Defenses Tests
# ============================================================================

def test_ssrf_private_ips_rejected():
    private_targets = [
        "http://127.0.0.1/admin",
        "http://localhost:8000/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.1/router",
        "http://192.168.1.1/setup",
        "http://172.16.0.1/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ]
    for url in private_targets:
        val = SafeURLInspector.validate_url(url)
        assert not val.is_safe
        assert any(term in (val.reason or "").lower() for term in ["blocked", "private", "metadata", "internal"])


# ============================================================================
# 3. Domain & Subdomain Intelligence Tests
# ============================================================================

def test_domain_details_extraction_brand_subdomain_spoofing():
    url = "http://paypal.com.verification-center.xyz/login/verify?account=active"
    details = SafeURLInspector.extract_domain_details(url)

    assert details["hostname"] == "paypal.com.verification-center.xyz"
    assert details["root_domain"] == "verification-center.xyz"
    assert details["tld"] == "xyz"
    assert details["subdomains"] == ["paypal", "com"]
    assert details["subdomain_brand_deception"] is True
    assert "paypal" in details["deceptive_brands_found"]
    assert details["has_high_risk_tld"] is True
    assert "login" in details["sensitive_path_keywords"]
    assert "verify" in details["sensitive_path_keywords"]


def test_domain_details_raw_ip_and_punycode():
    raw_ip_url = "http://198.51.100.25:8080/payload.exe"
    details_ip = SafeURLInspector.extract_domain_details(raw_ip_url)
    assert details_ip["is_ip_address"] is True
    assert details_ip["port"] == 8080

    punycode_url = "https://xn--pple-43d.com/support"
    details_puny = SafeURLInspector.extract_domain_details(punycode_url)
    assert details_puny["is_punycode"] is True


def test_two_part_cctld_handling():
    url = "https://online.banking.co.uk/secure"
    details = SafeURLInspector.extract_domain_details(url)
    assert details["root_domain"] == "banking.co.uk"
    assert details["tld"] == "co.uk"
    assert details["subdomains"] == ["online"]


# ============================================================================
# 4. Redirect-Chain Analysis Tests
# ============================================================================

@pytest.mark.asyncio
async def test_redirect_chain_ssrf_blocked_on_subsequent_hop():
    import httpx
    # If hop 0 targets a valid URL that redirects to 169.254.169.254
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp_redirect = httpx.Response(
            302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
            request=httpx.Request("GET", "https://example.com/redirect"),
        )
        mock_get.return_value = mock_resp_redirect

        result = await SafeURLInspector.fetch_head_or_preview("https://example.com/redirect")
        assert result["success"] is False
        assert "169.254.169.254" in result["final_url"]
        assert "security check failed" in result["error"].lower()


@pytest.mark.asyncio
async def test_redirect_chain_cross_domain_detected():
    import httpx
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp_final = httpx.Response(
            200,
            text="<html>Landing page</html>",
            headers={"server": "cloudflare", "content-type": "text/html"},
            request=httpx.Request("GET", "https://different-domain.com/landing"),
        )
        mock_get.return_value = mock_resp_final

        result = await SafeURLInspector.fetch_head_or_preview("https://short.link/xyz")
        assert result["success"] is True
        assert result["is_cross_domain_redirect"] is True
        assert result["server"] == "cloudflare"


# ============================================================================
# 5. Multi-Provider Threat Intel & Disagreement Tests
# ============================================================================

@pytest.mark.asyncio
async def test_threat_intel_agent_provider_disagreement():
    from app.agents.threat_intelligence import ThreatIntelligenceAgent

    target_url = "http://phish-test.top/login"
    agent = ThreatIntelligenceAgent()

    # Mock VT as clean
    rec_vt = NormalizedEvidenceRecord(
        provider_name="VirusTotal",
        query_type="url",
        query_target=target_url,
        status=ProviderStatus.OK,
        is_malicious=False,
    )
    # Mock URLhaus as confirmed malware
    rec_uh = NormalizedEvidenceRecord(
        provider_name="URLhaus",
        query_type="url",
        query_target=target_url,
        status=ProviderStatus.CONFIRMED_MATCH,
        is_malicious=True,
        is_malware=True,
        threat_description="Active trojan payload",
    )
    # Mock PhishTank as not found
    rec_pt = NormalizedEvidenceRecord(
        provider_name="PhishTank",
        query_type="url",
        query_target=target_url,
        status=ProviderStatus.NO_MATCH,
        is_malicious=False,
    )

    with patch.object(agent, "investigate_url", AsyncMock(return_value=[rec_vt, rec_uh, rec_pt])):
        output, records = await agent.analyze([target_url])

        assert output.any_malicious_detected is True
        assert output.malware_detected is True
        assert output.provider_consensus in ("confirmed_malware", "disagreement")
        assert len(output.provider_disagreements) == 1
        assert "URLhaus" in output.provider_disagreements[0]
        assert "VirusTotal" in output.provider_disagreements[0]
        assert target_url in output.domain_analysis


# ============================================================================
# 6. Risk Engine Unknown URL Safety Policy
# ============================================================================

def test_risk_engine_unverified_url_never_classified_as_low():
    # When URL has no external detections because providers are unconfigured/unavailable
    ev_unavail = NormalizedEvidenceRecord(
        provider_name="VirusTotal",
        query_type="url",
        query_target="http://untested-link.net",
        status=ProviderStatus.NOT_CONFIGURED,
        is_malicious=False,
    )

    threat_output = ThreatIntelligenceOutput(
        checked_urls=["http://untested-link.net"],
        records=[],
        any_malicious_detected=False,
        provider_consensus="unknown",
    )

    assessment = DeterministicRiskEngine.calculate_risk(
        threat_intel=threat_output,
        evidence_records=[ev_unavail],
        provider_statuses={"VirusTotal": "not_configured"},
    )

    # Must be "unknown" risk, NOT "low"
    assert assessment.risk_level == "unknown"
    assert any("cannot be classified as safe" in lim for lim in assessment.limitations)


# ============================================================================
# 7. End-to-End URL Investigation API Tests
# ============================================================================

@pytest.mark.asyncio
async def test_api_investigate_url_ssrf_attempt_rejected(client: AsyncClient):
    payload = {"url": "http://169.254.169.254/latest/meta-data/"}
    resp = await client.post(f"{settings.API_V1_STR}/investigations/url", json=payload)
    assert resp.status_code == 400
    assert "rejected by security inspector" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_api_investigate_url_confirmed_phishing(client: AsyncClient):
    phish_url = "http://chase.com.login-verify.top/auth"

    rec_pt = NormalizedEvidenceRecord(
        provider_name="PhishTank",
        query_type="url",
        query_target=phish_url,
        status=ProviderStatus.CONFIRMED_MATCH,
        is_malicious=True,
        is_phishing=True,
        threat_description="Verified phishing page targeting Chase customers",
    )

    with patch("app.agents.threat_intelligence.ThreatIntelligenceAgent.investigate_url", AsyncMock(return_value=[rec_pt])):
        resp = await client.post(
            f"{settings.API_V1_STR}/investigations/url",
            json={"url": phish_url, "context_notes": "Received in suspicious SMS"},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["input_type"] == "url"
        assert data["final_risk_level"] in ("high", "critical")
        assert data["final_risk_score"] >= 70.0
        assert any("phishing" in ind.lower() for ind in data["observed_indicators"])
        assert any("chase.com.login-verify.top" in u for u in data["extracted_urls"])

        # Check URL artifact in DB
        url_arts = [a for a in data["artifacts"] if a["artifact_type"] == "url"]
        assert len(url_arts) == 1
        assert "chase" in url_arts[0]["filename"]


@pytest.mark.asyncio
async def test_api_investigate_url_clean_reputation(client: AsyncClient):
    clean_url = "https://www.wikimedia.org/"

    rec_vt = NormalizedEvidenceRecord(
        provider_name="VirusTotal",
        query_type="url",
        query_target=clean_url,
        status=ProviderStatus.OK,
        is_malicious=False,
    )
    rec_pt = NormalizedEvidenceRecord(
        provider_name="PhishTank",
        query_type="url",
        query_target=clean_url,
        status=ProviderStatus.NO_MATCH,
        is_malicious=False,
    )
    rec_uh = NormalizedEvidenceRecord(
        provider_name="URLhaus",
        query_type="url",
        query_target=clean_url,
        status=ProviderStatus.NO_MATCH,
        is_malicious=False,
    )

    with patch("app.agents.threat_intelligence.ThreatIntelligenceAgent.investigate_url", AsyncMock(return_value=[rec_vt, rec_pt, rec_uh])):
        resp = await client.post(
            f"{settings.API_V1_STR}/investigations/url",
            json={"url": clean_url},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["input_type"] == "url"
        assert data["final_risk_level"] == "low"
        assert data["final_risk_score"] <= 30.0
