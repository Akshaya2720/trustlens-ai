"""TrustLens AI - Google Fact Check Tools API Adapter

Official documentation: https://developers.google.com/fact-check/tools/api
Queries genuine fact-checking databases for claims, citations, ratings, and publishers.
"""

import time
from typing import Any, Dict, List, Optional
import httpx
from pydantic import BaseModel
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.config import settings
from app.core.logging import logger


class FactCheckReview(BaseModel):
    publisher_name: str
    publisher_site: Optional[str] = None
    url: str
    title: Optional[str] = None
    review_date: Optional[str] = None
    textual_rating: str


class FactCheckClaimResult(BaseModel):
    claim_text: str
    claimant: Optional[str] = None
    claim_date: Optional[str] = None
    reviews: List[FactCheckReview] = []
    verdict_category: str  # "false", "misleading", "partly_true", "true", "unverified"


class GoogleFactCheckClient:
    """Client for Google Fact Check Tools ClaimSearch API."""

    BASE_URL = "https://factchecktools.googleapis.com/v1alpha1/claims:search"

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or settings.GOOGLE_FACTCHECK_API_KEY

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    @staticmethod
    def categorize_rating(rating: str) -> str:
        """Normalizes textual ratings from various publishers into standard buckets."""
        r = rating.lower().strip()
        if any(w in r for w in ["false", "pants on fire", "fake", "hoax", "incorrect", "debunked", "fabricated"]):
            return "false"
        elif any(w in r for w in ["misleading", "altered", "distorts", "exaggerates", "missing context"]):
            return "misleading"
        elif any(w in r for w in ["partly true", "mostly false", "half true", "mixture"]):
            return "partly_true"
        elif any(w in r for w in ["true", "correct", "accurate"]):
            return "true"
        return "disputed"

    async def search_claim(self, claim: str, language_code: str = "en") -> tuple[NormalizedEvidenceRecord, List[FactCheckClaimResult]]:
        """Searches Google Fact Check ClaimSearch API for third-party verified fact checks."""
        if not self.is_configured:
            record = NormalizedEvidenceRecord(
                provider_name="GoogleFactCheck",
                query_type="claim",
                query_target=claim,
                status=ProviderStatus.NOT_CONFIGURED,
                error_message="GOOGLE_FACTCHECK_API_KEY is not configured.",
            )
            return record, []

        params = {
            "query": claim,
            "key": self.api_key,
            "languageCode": language_code,
        }

        start_time = time.perf_counter()
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(self.BASE_URL, params=params)

            latency_ms = (time.perf_counter() - start_time) * 1000.0

            if resp.status_code == 200:
                data = resp.json()
                raw_claims = data.get("claims", [])

                if not raw_claims:
                    record = NormalizedEvidenceRecord(
                        provider_name="GoogleFactCheck",
                        query_type="claim",
                        query_target=claim,
                        status=ProviderStatus.NO_MATCH,
                        threat_description="No matching fact-checks found in Google Fact Check database. (Claim remains unverified).",
                        latency_ms=round(latency_ms, 2),
                    )
                    return record, []

                parsed_results: List[FactCheckClaimResult] = []
                has_debunked = False
                first_source_url = None

                for c in raw_claims:
                    reviews: List[FactCheckReview] = []
                    dominant_category = "unverified"

                    for r in c.get("claimReview", []):
                        pub = r.get("publisher", {})
                        rating_text = r.get("textualRating", "Unrated")
                        cat = self.categorize_rating(rating_text)
                        if cat in ("false", "misleading"):
                            has_debunked = True
                            dominant_category = cat

                        review_url = r.get("url", "")
                        if not first_source_url and review_url:
                            first_source_url = review_url

                        reviews.append(
                            FactCheckReview(
                                publisher_name=pub.get("name", "Unknown Publisher"),
                                publisher_site=pub.get("site"),
                                url=review_url,
                                title=r.get("title"),
                                review_date=r.get("reviewDate"),
                                textual_rating=rating_text,
                            )
                        )

                    parsed_results.append(
                        FactCheckClaimResult(
                            claim_text=c.get("text", claim),
                            claimant=c.get("claimant"),
                            claim_date=c.get("claimDate"),
                            reviews=reviews,
                            verdict_category=dominant_category,
                        )
                    )

                status = ProviderStatus.CONFIRMED_MATCH if has_debunked else ProviderStatus.OK
                desc = (
                    f"Found {len(parsed_results)} claim record(s). "
                    f"Verified reviews indicate: {'False / Misleading claim detected' if has_debunked else 'Verified sources reviewed claim'}."
                )

                record = NormalizedEvidenceRecord(
                    provider_name="GoogleFactCheck",
                    query_type="claim",
                    query_target=claim,
                    status=status,
                    is_malicious=has_debunked,
                    threat_description=desc,
                    raw_details={"claims_count": len(parsed_results), "claims": [p.model_dump() for p in parsed_results]},
                    source_reference=first_source_url or "https://toolbox.google.com/factcheck/explorer",
                    latency_ms=round(latency_ms, 2),
                )
                return record, parsed_results

            elif resp.status_code == 429:
                return (
                    NormalizedEvidenceRecord(
                        provider_name="GoogleFactCheck",
                        query_type="claim",
                        query_target=claim,
                        status=ProviderStatus.RATE_LIMITED,
                        error_message="Google Fact Check API rate limit exceeded.",
                        latency_ms=round(latency_ms, 2),
                    ),
                    [],
                )
            elif resp.status_code in (401, 403):
                return (
                    NormalizedEvidenceRecord(
                        provider_name="GoogleFactCheck",
                        query_type="claim",
                        query_target=claim,
                        status=ProviderStatus.UNAUTHORIZED,
                        error_message="Invalid Google Fact Check API key or unauthorized project.",
                        latency_ms=round(latency_ms, 2),
                    ),
                    [],
                )
            else:
                return (
                    NormalizedEvidenceRecord(
                        provider_name="GoogleFactCheck",
                        query_type="claim",
                        query_target=claim,
                        status=ProviderStatus.ERROR,
                        error_message=f"HTTP {resp.status_code}: {resp.text[:200]}",
                        latency_ms=round(latency_ms, 2),
                    ),
                    [],
                )

        except Exception as e:
            logger.warning(f"Google Fact Check API error: {e}")
            return (
                NormalizedEvidenceRecord(
                    provider_name="GoogleFactCheck",
                    query_type="claim",
                    query_target=claim,
                    status=ProviderStatus.UNAVAILABLE,
                    error_message=str(e),
                    latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
                ),
                [],
            )
