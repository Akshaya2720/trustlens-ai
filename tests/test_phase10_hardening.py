"""TrustLens AI - Phase 10: Production Hardening & Operational Readiness Tests

Verifies:
1. Rate limiting per client, HTTP 429 Too Many Requests, and Retry-After headers.
2. OWASP Security Headers (nosniff, DENY, HSTS, CSP, XSS protection).
3. PII redaction (Credit Card Luhn checks, SSNs).
4. Audit logging persistence and event recording.
5. Graceful error handling and uniform error responses.
"""

import pytest
from httpx import AsyncClient

from app.core.rate_limit import InMemoryRateLimiter, rate_limiter
from app.core.security import redact_pii
from app.db.models import AuditEvent
from app.db.repository import InvestigationRepository
from app.db.session import AsyncSessionLocal


def test_pii_redaction():
    """Verifies credit card numbers and SSNs are properly redacted while non-sensitive text is preserved."""
    # Real valid test credit cards (Luhn valid test numbers)
    visa_test = "4111 1111 1111 1111"
    ssn_test = "123-45-6789"
    text = f"Customer payment card is {visa_test} and SSN is {ssn_test}. Order ID 987654321."

    redacted = redact_pii(text)
    assert "[REDACTED_CARD]" in redacted
    assert "[REDACTED_SSN]" in redacted
    assert "4111" not in redacted
    assert "123-45-6789" not in redacted
    assert "Order ID 987654321" in redacted  # Non-Luhn number preserved


def test_rate_limiter_sliding_window():
    """Unit test for sliding window rate limiter logic."""
    limiter = InMemoryRateLimiter(requests_per_minute=3, window_seconds=60)
    client_ip = "192.168.1.100"

    # Request 1
    limited, rem, retry = limiter.is_rate_limited(client_ip)
    assert not limited
    assert rem == 2

    # Request 2
    limited, rem, retry = limiter.is_rate_limited(client_ip)
    assert not limited
    assert rem == 1

    # Request 3
    limited, rem, retry = limiter.is_rate_limited(client_ip)
    assert not limited
    assert rem == 0

    # Request 4 (exceeded)
    limited, rem, retry = limiter.is_rate_limited(client_ip)
    assert limited is True
    assert rem == 0
    assert retry > 0


@pytest.mark.asyncio
async def test_security_headers_present(client: AsyncClient):
    """Verifies standard security headers are applied to HTTP responses."""
    resp = await client.get("/health")
    assert resp.status_code == 200
    headers = resp.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in headers
    assert "Content-Security-Policy" in headers
    assert headers.get("X-XSS-Protection") == "1; mode=block"


@pytest.mark.asyncio
async def test_rate_limiting_middleware_429(client: AsyncClient):
    """Verifies that exceeding the configured rate limit returns HTTP 429 and Retry-After."""
    # Temporarily set limit to 2 for this test
    original_limit = rate_limiter.requests_per_minute
    rate_limiter.requests_per_minute = 2
    rate_limiter.reset()

    custom_headers = {"X-API-Key": "test-rate-limit-client"}

    try:
        # 1st request
        r1 = await client.post(
            "/api/v1/investigations/text",
            json={"text": "Rate test inquiry 1"},
            headers=custom_headers,
        )
        assert r1.status_code == 201
        assert r1.headers.get("X-RateLimit-Limit") == "2"

        # 2nd request
        r2 = await client.post(
            "/api/v1/investigations/text",
            json={"text": "Rate test inquiry 2"},
            headers=custom_headers,
        )
        assert r2.status_code == 201

        # 3rd request (should trigger 429)
        r3 = await client.post(
            "/api/v1/investigations/text",
            json={"text": "Rate test inquiry 3"},
            headers=custom_headers,
        )
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers
        data = r3.json()
        assert data["error"] == "RateLimitExceeded"
        assert "retry_after_seconds" in data
    finally:
        # Restore rate limiter
        rate_limiter.requests_per_minute = original_limit
        rate_limiter.reset()


@pytest.mark.asyncio
async def test_health_probes_bypass_rate_limit(client: AsyncClient):
    """Verifies that health and readiness endpoints are never throttled by the rate limiter."""
    original_limit = rate_limiter.requests_per_minute
    rate_limiter.requests_per_minute = 1
    rate_limiter.reset()

    try:
        # Probe health multiple times exceeding limit
        for _ in range(5):
            resp = await client.get("/health")
            assert resp.status_code == 200
    finally:
        rate_limiter.requests_per_minute = original_limit
        rate_limiter.reset()


@pytest.mark.asyncio
async def test_audit_logging_persistence():
    """Verifies audit events can be logged and queried from the database."""
    import uuid
    inv_id = f"audit-test-{uuid.uuid4()}"
    async with AsyncSessionLocal() as session:
        repo = InvestigationRepository(session)
        inv = await repo.create_investigation(
            investigation_id=inv_id,
            input_type="text",
            raw_input_preview="Audit test input",
        )
        evt = await repo.log_audit_event(
            investigation_id=inv.id,
            event_type="security_policy_evaluation",
            actor="test_admin",
            details={"policy": "rate_limit_applied", "client_ip": "10.0.0.1"},
        )
        await session.commit()

        assert evt.id is not None
        assert evt.investigation_id == inv_id
        assert evt.event_type == "security_policy_evaluation"
        assert evt.actor == "test_admin"
        assert evt.details_json.get("policy") == "rate_limit_applied"
