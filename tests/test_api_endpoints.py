"""TrustLens AI - FastAPI Endpoints Integration Tests"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_endpoint(client: AsyncClient):
    resp = await client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "version" in data


@pytest.mark.asyncio
async def test_readiness_endpoint(client: AsyncClient):
    resp = await client.get("/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["database"] == "ok"
    assert "external_providers" in data


@pytest.mark.asyncio
async def test_text_investigation_endpoint(client: AsyncClient):
    payload = {
        "text": "URGENT: Your account has been suspended! Click http://phish-test.xyz to verify your identity.",
        "sender_hint": "Support Desk",
    }
    resp = await client.post("/api/v1/investigations/text", json=payload)
    assert resp.status_code == 201
    data = resp.json()

    assert "investigation_id" in data
    assert data["input_type"] == "text"
    assert data["status"] == "completed"
    assert data["final_risk_level"] in ("low", "medium", "high", "critical", "unknown")
    assert len(data["artifacts"]) >= 1

    inv_id = data["investigation_id"]

    # Test GET investigation report
    get_resp = await client.get(f"/api/v1/investigations/{inv_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["investigation_id"] == inv_id

    # Test GET status
    status_resp = await client.get(f"/api/v1/investigations/{inv_id}/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "completed"

    # Test GET evidence
    ev_resp = await client.get(f"/api/v1/investigations/{inv_id}/evidence")
    assert ev_resp.status_code == 200
    assert "evidence" in ev_resp.json()

    # Test POST question
    q_payload = {"question": "What is the risk level of this message?"}
    q_resp = await client.post(f"/api/v1/investigations/{inv_id}/questions", json=q_payload)
    assert q_resp.status_code == 200
    q_data = q_resp.json()
    assert q_data["investigation_id"] == inv_id
    assert q_data["grounded_in_evidence"] is True
    assert len(q_data["answer"]) > 0


@pytest.mark.asyncio
async def test_url_investigation_endpoint(client: AsyncClient):
    payload = {"url": "https://www.wikipedia.org"}
    resp = await client.post("/api/v1/investigations/url", json=payload)
    assert resp.status_code == 201
    data = resp.json()
    assert data["input_type"] == "url"
    assert data["status"] == "completed"


@pytest.mark.asyncio
async def test_url_investigation_blocks_ssrf(client: AsyncClient):
    payload = {"url": "http://127.0.0.1:8080/secret"}
    resp = await client.post("/api/v1/investigations/url", json=payload)
    assert resp.status_code == 400
    assert "rejected by security inspector" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_nonexistent_investigation_returns_404(client: AsyncClient):
    resp = await client.get("/api/v1/investigations/non-existent-uuid-1234")
    assert resp.status_code == 404
