"""TrustLens AI - VirusTotal v3 Adapter

Official documentation: https://docs.virustotal.com/docs/api-overview
Provides URL and Domain reputation retrieval, engine consensus parsing,
and deterministic status mapping.
"""

import base64
import time
from typing import Optional
from urllib.parse import urlparse
import httpx
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.config import settings
from app.core.logging import logger


class VirusTotalClient:
    """VirusTotal API v3 Client."""

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.VIRUSTOTAL_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    @staticmethod
    def encode_url_id(url: str) -> str:
        """Encodes URL to base64url format without padding as per VT v3 spec."""
        return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    async def check_url(self, url: str) -> NormalizedEvidenceRecord:
        """Queries VirusTotal for historical or real-time URL analysis stats."""
        if not self.is_configured:
            return NormalizedEvidenceRecord(
                provider_name="VirusTotal",
                query_type="url",
                query_target=url,
                status=ProviderStatus.NOT_CONFIGURED,
                error_message="VirusTotal API key is not configured.",
            )

        url_id = self.encode_url_id(url)
        endpoint = f"{self.BASE_URL}/urls/{url_id}"
        headers = {
            "x-apikey": self.api_key,
            "User-Agent": "TrustLens-Safety-Scanner/1.0",
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(endpoint, headers=headers)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 200:
                data = resp.json().get("data", {})
                attributes = data.get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)
                harmless_count = stats.get("harmless", 0)
                total_engines = sum(stats.values()) if stats else 0

                is_malicious = malicious_count >= 2 or (malicious_count == 1 and suspicious_count >= 2)
                status = ProviderStatus.CONFIRMED_MATCH if is_malicious else ProviderStatus.OK

                threat_desc = (
                    f"Detections: {malicious_count} malicious, {suspicious_count} suspicious "
                    f"out of {total_engines} engines."
                )

                return NormalizedEvidenceRecord(
                    provider_name="VirusTotal",
                    query_type="url",
                    query_target=url,
                    status=status,
                    is_malicious=is_malicious,
                    is_phishing="phishing" in str(attributes.get("categories", {})).lower(),
                    is_malware="malware" in str(attributes.get("categories", {})).lower(),
                    threat_description=threat_desc,
                    confidence_score=round(min(1.0, (malicious_count * 20) / 100.0), 2) if total_engines else None,
                    raw_details={
                        "stats": stats,
                        "reputation": attributes.get("reputation"),
                        "categories": attributes.get("categories"),
                        "last_analysis_date": attributes.get("last_analysis_date"),
                    },
                    source_reference=f"https://www.virustotal.com/gui/url/{url_id}",
                    latency_ms=round(latency_ms, 2),
                )

            elif resp.status_code == 404:
                return NormalizedEvidenceRecord(
                    provider_name="VirusTotal",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.NO_MATCH,
                    threat_description="URL has not been previously analyzed in VirusTotal database.",
                    source_reference=f"https://www.virustotal.com/gui/url/{url_id}",
                    latency_ms=round(latency_ms, 2),
                )
            elif resp.status_code == 429:
                return NormalizedEvidenceRecord(
                    provider_name="VirusTotal",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.RATE_LIMITED,
                    error_message="VirusTotal API quota/rate limit exceeded.",
                    latency_ms=round(latency_ms, 2),
                )
            elif resp.status_code in (401, 403):
                return NormalizedEvidenceRecord(
                    provider_name="VirusTotal",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.UNAUTHORIZED,
                    error_message="Invalid or unauthorized VirusTotal API key.",
                    latency_ms=round(latency_ms, 2),
                )
            else:
                return NormalizedEvidenceRecord(
                    provider_name="VirusTotal",
                    query_type="url",
                    query_target=url,
                    status=ProviderStatus.ERROR,
                    error_message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                    latency_ms=round(latency_ms, 2),
                )

        except Exception as e:
            logger.warning(f"VirusTotal lookup error: {e}")
            return NormalizedEvidenceRecord(
                provider_name="VirusTotal",
                query_type="url",
                query_target=url,
                status=ProviderStatus.UNAVAILABLE,
                error_message=str(e),
                latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
            )
