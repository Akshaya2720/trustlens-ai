"""TrustLens AI - URLhaus Adapter

Official documentation: https://urlhaus.abuse.ch/api/
Retrieves verified malware distribution data from abuse.ch URLhaus.
"""

import time
from typing import Optional
import httpx
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.config import settings
from app.core.logging import logger


class URLhausClient:
    """URLhaus (abuse.ch) API Client."""

    BASE_URL = "https://urlhaus-api.abuse.ch/v1"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.URLHAUS_API_KEY

    async def check_url(self, url: str) -> NormalizedEvidenceRecord:
        """Queries URLhaus for verified active/historical malware hosting records."""
        endpoint = f"{self.BASE_URL}/url/"
        data = {"url": url}
        headers = {
            "User-Agent": "TrustLens-Safety-Scanner/1.0",
        }
        if self.api_key:
            headers["Auth-Key"] = self.api_key

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(endpoint, data=data, headers=headers)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 200:
                result = resp.json()
                query_status = result.get("query_status")

                if query_status == "ok":
                    urlhaus_id = result.get("id")
                    threat = result.get("threat", "malware_download")
                    url_status = result.get("url_status", "unknown")
                    tags = result.get("tags", [])

                    threat_desc = f"Verified malware distribution site ({threat}). Status: {url_status}. Tags: {tags}"

                    return NormalizedEvidenceRecord(
                        provider_name="URLhaus",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.CONFIRMED_MATCH,
                        is_malicious=True,
                        is_malware=True,
                        is_phishing=False,
                        threat_description=threat_desc,
                        confidence_score=0.98,
                        raw_details=result,
                        source_reference=f"https://urlhaus.abuse.ch/url/{urlhaus_id}/" if urlhaus_id else "https://urlhaus.abuse.ch/",
                        latency_ms=round(latency_ms, 2),
                    )

                elif query_status == "no_results":
                    return NormalizedEvidenceRecord(
                        provider_name="URLhaus",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.NO_MATCH,
                        is_malicious=False,
                        is_malware=False,
                        threat_description="URL is not listed in URLhaus malware database (note: absence of listing does not prove safety).",
                        source_reference="https://urlhaus.abuse.ch/",
                        latency_ms=round(latency_ms, 2),
                    )

                elif query_status == "invalid_url":
                    return NormalizedEvidenceRecord(
                        provider_name="URLhaus",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.INVALID_REQUEST,
                        error_message="URLhaus reported the submitted URL is invalid.",
                        latency_ms=round(latency_ms, 2),
                    )
                else:
                    return NormalizedEvidenceRecord(
                        provider_name="URLhaus",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.ERROR,
                        error_message=f"Unexpected query_status: {query_status}",
                        latency_ms=round(latency_ms, 2),
                    )

            elif resp.status_code in (401, 403):
                return NormalizedEvidenceRecord(
                    provider_name="URLhaus",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_message=f"URLhaus authentication required: {resp.text[:200]}",
                    latency_ms=round(latency_ms, 2),
                )
            elif resp.status_code == 429:
                return NormalizedEvidenceRecord(
                    provider_name="URLhaus",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.RATE_LIMITED,
                    error_message="URLhaus rate limit reached.",
                    latency_ms=round(latency_ms, 2),
                )
            else:
                return NormalizedEvidenceRecord(
                    provider_name="URLhaus",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.ERROR,
                    error_message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=round(latency_ms, 2),
                )

        except Exception as e:
            logger.warning(f"URLhaus lookup error: {e}")
            return NormalizedEvidenceRecord(
                provider_name="URLhaus",
                query_type="url",
                query_target=url,
                status=ProviderStatus.UNAVAILABLE,
                error_message=str(e),
                latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )
