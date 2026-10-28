"""TrustLens AI - PhishTank Adapter

Official documentation: https://phishtank.org/api_info.php
Checks submitted URLs against PhishTank verified phishing records.
"""

import time
from typing import Optional
import httpx
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.config import settings
from app.core.logging import logger


class PhishTankClient:
    """PhishTank API Client."""

    CHECK_URL = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.PHISHTANK_API_KEY

    async def check_url(self, url: str) -> NormalizedEvidenceRecord:
        """Queries PhishTank for verified active phishing records."""
        data = {
            "url": url,
            "format": "json",
        }
        if self.api_key:
            data["app_key"] = self.api_key

        headers = {
            "User-Agent": "phishtank/TrustLens-Safety-Scanner-1.0",
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(self.CHECK_URL, data=data, headers=headers)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 200:
                body = resp.json()
                results = body.get("results", {})

                in_database = results.get("in_database", False)
                valid = results.get("valid", False) or results.get("valid") == "y"
                verified = results.get("verified", False) or results.get("verified") == "y"
                phish_id = results.get("phish_id")
                phish_detail_page = results.get("phish_detail_page")

                if in_database and valid:
                    threat_desc = f"Verified active phishing page in PhishTank (ID: {phish_id}, Verified: {verified})"
                    return NormalizedEvidenceRecord(
                        provider_name="PhishTank",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.CONFIRMED_MATCH,
                        is_malicious=True,
                        is_phishing=True,
                        is_malware=False,
                        threat_description=threat_desc,
                        confidence_score=0.95,
                        raw_details=results,
                        source_reference=phish_detail_page or f"https://phishtank.org/phish_detail.php?phish_id={phish_id}",
                        latency_ms=round(latency_ms, 2),
                    )
                else:
                    return NormalizedEvidenceRecord(
                        provider_name="PhishTank",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.NO_MATCH,
                        is_malicious=False,
                        is_phishing=False,
                        threat_description="URL not found in PhishTank verified records (note: unlisted does not equal safe).",
                        source_reference="https://phishtank.org",
                        raw_details=results,
                        latency_ms=round(latency_ms, 2),
                    )

            elif resp.status_code == 429:
                return NormalizedEvidenceRecord(
                    provider_name="PhishTank",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.RATE_LIMITED,
                    error_message="PhishTank rate limit reached.",
                    latency_ms=round(latency_ms, 2),
                )
            else:
                return NormalizedEvidenceRecord(
                    provider_name="PhishTank",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.ERROR,
                    error_message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=round(latency_ms, 2),
                )

        except Exception as e:
            logger.warning(f"PhishTank lookup error: {e}")
            return NormalizedEvidenceRecord(
                provider_name="PhishTank",
                query_type="url",
                query_target=url,
                status=ProviderStatus.UNAVAILABLE,
                error_message=str(e),
                latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )
