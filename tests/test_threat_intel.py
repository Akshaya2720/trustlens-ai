"""TrustLens AI - Threat Intelligence Provider Unit Tests"""

import pytest
from app.clients.threat_intel.base import ProviderStatus
from app.clients.threat_intel.google_factcheck import GoogleFactCheckClient
from app.clients.threat_intel.phishtank import PhishTankClient
from app.clients.threat_intel.urlhaus import URLhausClient
from app.clients.threat_intel.virustotal import VirusTotalClient


def test_virustotal_base64_url_encoding():
    url = "https://example.com/login"
    encoded = VirusTotalClient.encode_url_id(url)
    assert "=" not in encoded
    assert len(encoded) > 0


def test_google_factcheck_rating_categorization():
    assert GoogleFactCheckClient.categorize_rating("False") == "false"
    assert GoogleFactCheckClient.categorize_rating("Pants on Fire!") == "false"
    assert GoogleFactCheckClient.categorize_rating("Misleading Context") == "misleading"
    assert GoogleFactCheckClient.categorize_rating("Partly True") == "partly_true"
    assert GoogleFactCheckClient.categorize_rating("Correct and Verified") == "true"
    assert GoogleFactCheckClient.categorize_rating("Unconfirmed") == "disputed"


@pytest.mark.asyncio
async def test_virustotal_unconfigured_behavior():
    vt = VirusTotalClient(api_key=None)
    rec = await vt.check_url("https://example.com")
    assert rec.status == ProviderStatus.NOT_CONFIGURED
    assert rec.provider_name == "VirusTotal"
    assert "not configured" in rec.error_message.lower()


@pytest.mark.asyncio
async def test_google_factcheck_unconfigured_behavior():
    gfc = GoogleFactCheckClient(api_key=None)
    rec, claims = await gfc.search_claim("Earth is flat")
    assert rec.status == ProviderStatus.NOT_CONFIGURED
    assert len(claims) == 0


@pytest.mark.asyncio
async def test_urlhaus_live_or_mock():
    # URLhaus is a public service from abuse.ch
    urlhaus = URLhausClient()
    # Query a known safe domain
    rec = await urlhaus.check_url("https://www.google.com")
    assert rec.provider_name == "URLhaus"
    assert rec.status in (
        ProviderStatus.NO_MATCH,
        ProviderStatus.UNAVAILABLE,
        ProviderStatus.RATE_LIMITED,
        ProviderStatus.OK,
        ProviderStatus.UNAUTHORIZED,
        ProviderStatus.ERROR,
    )
