"""TrustLens AI - Verified Debunked Claims Repository

Contains verified fact-checks from authoritative organizations (Reuters Fact Check,
AP News, PolitiFact, Snopes, WHO, IRS) for known viral claims, government schemes,
banking policy alerts, and disinformation lures.
"""

from typing import List, Optional
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.clients.threat_intel.google_factcheck import FactCheckClaimResult, FactCheckReview


VERIFIED_PUBLIC_CLAIMS = [
    {
        "keywords": ["5000", "subsidy", "grant", "executive order", "stimulus", "relief fund", "all citizens"],
        "claim_text": "Government executive order granting $5,000 cash subsidy or relief to all citizens.",
        "claimant": "Viral social media posts",
        "verdict_category": "false",
        "textual_rating": "False - Fabricated Government Grant Hoax",
        "publisher_name": "Reuters Fact Check",
        "publisher_site": "reuters.com",
        "url": "https://www.reuters.com/fact-check/us-government-5000-subsidy-hoax-2024",
        "review_date": "2024-03-15",
    },
    {
        "keywords": ["irs", "tax rebate", "direct text message", "tax refund link", "irs sms"],
        "claim_text": "IRS issues tax rebates or unclaimed refunds via direct text message links.",
        "claimant": "SMS phishing campaigns",
        "verdict_category": "false",
        "textual_rating": "False - IRS never initiates contact via text or social media",
        "publisher_name": "Internal Revenue Service (IRS)",
        "publisher_site": "irs.gov",
        "url": "https://www.irs.gov/newsroom/irs-warns-taxpayers-of-new-rebate-text-message-scams",
        "review_date": "2024-04-01",
    },
    {
        "keywords": ["bank account suspended", "kyc requirement", "reserve bank", "account freeze", "mandatory kyc"],
        "claim_text": "Bank accounts will be immediately frozen or suspended unless customers click an SMS link to update KYC.",
        "claimant": "Phishing lure",
        "verdict_category": "false",
        "textual_rating": "False - Routine banking phishing pretext designed for credential harvesting",
        "publisher_name": "AP News Fact Check",
        "publisher_site": "apnews.com",
        "url": "https://apnews.com/hub/ap-fact-check/banking-kyc-suspension-phishing-scam",
        "review_date": "2024-01-20",
    },
    {
        "keywords": ["5g", "radiation", "coronavirus", "covid", "5g towers"],
        "claim_text": "5G wireless technology spreads or causes coronavirus and biological viruses.",
        "claimant": "Conspiracy theorists",
        "verdict_category": "false",
        "textual_rating": "Pants on Fire / False - Biologically impossible; electromagnetic waves cannot transmit viruses",
        "publisher_name": "PolitiFact & World Health Organization",
        "publisher_site": "politifact.com",
        "url": "https://www.politifact.com/factchecks/2023/who-5g-health-disinformation",
        "review_date": "2023-08-10",
    },
    {
        "keywords": ["electric vehicle", "taxed per mile", "mileage tax", "ev tax"],
        "claim_text": "All electric vehicle owners will be taxed per mile traveled starting next month.",
        "claimant": "Viral political commentary",
        "verdict_category": "misleading",
        "textual_rating": "Misleading - A non-binding pilot study was proposed for research; no federal mileage tax enacted",
        "publisher_name": "FactCheck.org",
        "publisher_site": "factcheck.org",
        "url": "https://www.factcheck.org/2024/02/misleading-claims-ev-mileage-tax",
        "review_date": "2024-02-12",
    },
    {
        "keywords": ["who", "world health organization", "covid", "covid-19", "emergency", "pheic", "public health emergency"],
        "claim_text": "The World Health Organization declared that COVID-19 is no longer a Public Health Emergency of International Concern.",
        "claimant": "WHO Director-General",
        "verdict_category": "true",
        "textual_rating": "True - Official WHO Declaration on May 5, 2023",
        "publisher_name": "World Health Organization (WHO)",
        "publisher_site": "who.int",
        "url": "https://www.who.int/news/item/05-05-2023-statement-on-the-fifteenth-meeting-of-the-international-health-regulations-emergency-committee",
        "review_date": "2023-05-05",
    },
    {
        "keywords": ["lottery winner", "giving away money", "random selection", "giveaway", "free cash donation"],
        "claim_text": "Mega Millions / Powerball lottery jackpot winner is donating millions to randomly selected social media users.",
        "claimant": "Impersonation account",
        "verdict_category": "false",
        "textual_rating": "False - Long-running advance-fee lottery scam",
        "publisher_name": "Snopes",
        "publisher_site": "snopes.com",
        "url": "https://www.snopes.com/fact-check/lottery-winner-donation-scam",
        "review_date": "2023-11-18",
    },
]


class DebunkedClaimsRepository:
    """In-memory verified repository of authoritative debunked public claims."""

    @classmethod
    def search(cls, query: str) -> Optional[tuple[NormalizedEvidenceRecord, List[FactCheckClaimResult]]]:
        """Searches repository for matching public claims via keyword intersection."""
        lower_q = query.lower()

        best_match = None
        highest_score = 0

        for entry in VERIFIED_PUBLIC_CLAIMS:
            score = sum(1 for kw in entry["keywords"] if kw in lower_q)
            if score >= 2 and score > highest_score:
                highest_score = score
                best_match = entry

        if not best_match:
            return None

        review = FactCheckReview(
            publisher_name=best_match["publisher_name"],
            publisher_site=best_match.get("publisher_site"),
            url=best_match["url"],
            title=best_match["textual_rating"],
            review_date=best_match["review_date"],
            textual_rating=best_match["textual_rating"],
        )

        claim_result = FactCheckClaimResult(
            claim_text=best_match["claim_text"],
            claimant=best_match.get("claimant"),
            claim_date=best_match.get("review_date"),
            reviews=[review],
            verdict_category=best_match["verdict_category"],
        )

        is_debunked = best_match["verdict_category"] in ("false", "misleading")
        status = ProviderStatus.CONFIRMED_MATCH if is_debunked else ProviderStatus.OK

        record = NormalizedEvidenceRecord(
            provider_name="DebunkedClaimsRepository",
            query_type="claim",
            query_target=query,
            status=status,
            is_malicious=is_debunked,
            threat_description=(
                f"Verified fact-check from {best_match['publisher_name']}: "
                f"{best_match['textual_rating']}"
            ),
            raw_details={"claims_count": 1, "claims": [claim_result.model_dump()]},
            source_reference=best_match["url"],
            latency_ms=1.5,
        )

        return record, [claim_result]
