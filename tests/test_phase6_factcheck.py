"""TrustLens AI - Phase 6 Fact-Checking & Misinformation Investigation Tests

Verifies the dedicated factual verification pipeline and `POST /api/v1/investigations/claim` endpoint:
- Extracting verifiable claims from public statements
- Querying Google Fact Check Tools API and DebunkedClaimsRepository
- Distinguishing debunked false claims, misleading claims, verified true announcements, and unverified assertions
- Validating publisher citations, review dates, URLs, and transparent limitations
"""

from unittest.mock import AsyncMock, patch
import httpx
import pytest
from app.clients.threat_intel.base import ProviderStatus
from app.clients.threat_intel.claims_repository import DebunkedClaimsRepository
from app.clients.threat_intel.google_factcheck import GoogleFactCheckClient
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_debunked_claims_repository_search():
    # Test matching a known debunked claim
    res = DebunkedClaimsRepository.search("The president announced a $5,000 cash subsidy grant for citizens")
    assert res is not None
    record, claim_results = res
    assert record.status == ProviderStatus.CONFIRMED_MATCH
    assert record.is_malicious is True
    assert "Reuters Fact Check" in record.threat_description
    assert len(claim_results) == 1
    assert claim_results[0].verdict_category == "false"
    assert "reuters.com" in claim_results[0].reviews[0].url


@pytest.mark.asyncio
async def test_debunked_claims_repository_no_match():
    # Test novel statement not in repository
    res = DebunkedClaimsRepository.search("A local bakery in Austin invented purple sourdough bread.")
    assert res is None


@pytest.mark.asyncio
async def test_google_factcheck_client_mock_api_success():
    mock_response_data = {
        "claims": [
            {
                "text": "Electric vehicles will be taxed $0.10 per mile starting next month.",
                "claimant": "Social media post",
                "claimDate": "2024-02-10",
                "claimReview": [
                    {
                        "publisher": {"name": "FactCheck.org", "site": "factcheck.org"},
                        "url": "https://www.factcheck.org/ev-tax-misleading",
                        "title": "Misleading claims about EV tax",
                        "reviewDate": "2024-02-12",
                        "textualRating": "Misleading",
                    }
                ],
            }
        ]
    }

    client = GoogleFactCheckClient(api_key="mock_test_key")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = httpx.Response(
            status_code=200,
            json=mock_response_data,
            request=httpx.Request("GET", "https://factchecktools.googleapis.com"),
        )
        mock_get.return_value = mock_resp

        record, results = await client.search_claim("Electric vehicles will be taxed per mile")
        assert record.status == ProviderStatus.CONFIRMED_MATCH
        assert record.is_malicious is True
        assert len(results) == 1
        assert results[0].reviews[0].publisher_name == "FactCheck.org"
        assert results[0].verdict_category == "misleading"


@pytest.mark.asyncio
async def test_google_factcheck_client_api_rate_limited():
    client = GoogleFactCheckClient(api_key="mock_test_key")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = httpx.Response(
            status_code=429,
            request=httpx.Request("GET", "https://factchecktools.googleapis.com"),
        )
        mock_get.return_value = mock_resp

        record, results = await client.search_claim("Any random claim")
        assert record.status == ProviderStatus.RATE_LIMITED
        assert len(results) == 0


@pytest.mark.asyncio
async def test_google_factcheck_client_api_unauthorized():
    client = GoogleFactCheckClient(api_key="invalid_key")
    with patch("httpx.AsyncClient.get") as mock_get:
        mock_resp = httpx.Response(
            status_code=403,
            request=httpx.Request("GET", "https://factchecktools.googleapis.com"),
        )
        mock_get.return_value = mock_resp

        record, results = await client.search_claim("Any claim")
        assert record.status == ProviderStatus.UNAUTHORIZED
        assert len(results) == 0


@pytest.mark.asyncio
async def test_api_investigate_claim_debunked_hoax(client: AsyncClient):
    resp = await client.post(
        "/api/v1/investigations/claim",
        json={
            "claim_text": "Government executive order granting $5000 subsidy relief to all citizens.",
            "context_notes": "Received on WhatsApp group claiming urgent money",
        },
    )

    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "claim"
    assert data["final_risk_level"] in ("high", "critical")
    assert data["final_risk_score"] >= 65.0
    assert len(data["verified_claims"]) >= 1
    assert any("Reuters Fact Check" in c for c in data["verified_claims"])
    assert len(data["evidence"]) >= 1
    assert data["evidence"][0]["provider_name"] in ("DebunkedClaimsRepository", "GoogleFactCheck")


@pytest.mark.asyncio
async def test_api_investigate_claim_verified_true(client: AsyncClient):
    resp = await client.post(
        "/api/v1/investigations/claim",
        json={
            "claim_text": "The World Health Organization declared the end of COVID-19 as a public health emergency (PHEIC).",
            "context_notes": "News channel discussion",
        },
    )

    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "claim"
    assert data["final_risk_level"] == "low"
    assert data["final_risk_score"] <= 30.0
    assert any("Verified authentic" in ind for ind in data["observed_indicators"])


@pytest.mark.asyncio
async def test_api_investigate_claim_unverified(client: AsyncClient):
    resp = await client.post(
        "/api/v1/investigations/claim",
        json={
            "claim_text": "New rare butterfly species with glowing wings discovered in northern Alaska.",
            "context_notes": "Social media video",
        },
    )

    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "claim"
    assert len(data["unverified_claims"]) >= 1
    assert any("unverified" in lim.lower() for lim in data["limitations"])


@pytest.mark.asyncio
async def test_api_investigate_claim_empty_validation(client: AsyncClient):
    resp = await client.post(
        "/api/v1/investigations/claim",
        json={"claim_text": "   "},
    )
    assert resp.status_code in (400, 422)
