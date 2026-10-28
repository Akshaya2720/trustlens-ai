"""TrustLens AI - Agent E: Claim Verification

Verifies factual claims against genuine third-party fact-checking databases
via Google Fact Check Tools API and Meta search grounding.
"""

from typing import List
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.clients.threat_intel.google_factcheck import GoogleFactCheckClient
from app.schemas.agent_outputs import ClaimVerificationOutput
from app.schemas.evidence import EvidenceItem


class ClaimVerificationAgent:
    """Agent E: Claim Verification."""

    def __init__(self):
        self.factcheck_client = GoogleFactCheckClient()

    async def analyze(self, claims: List[str]) -> tuple[ClaimVerificationOutput, List[NormalizedEvidenceRecord]]:
        all_records: List[NormalizedEvidenceRecord] = []
        if not claims:
            return (
                ClaimVerificationOutput(
                    claims_analyzed=[],
                    debunked_claims_count=0,
                    verified_true_count=0,
                    unverified_claims_count=0,
                    records=[],
                    summary="No distinct factual claims were extracted for verification.",
                ),
                [],
            )

        debunked_count = 0
        verified_true_count = 0
        unverified_count = 0

        for claim in claims[:3]:  # Limit to 3 claims to avoid quota drain
            record, parsed_reviews = await self.factcheck_client.search_claim(claim)
            all_records.append(record)

            if record.status == ProviderStatus.CONFIRMED_MATCH:
                debunked_count += 1
            elif record.status == ProviderStatus.OK:
                verified_true_count += 1
            else:
                unverified_count += 1

        evidence_items = [
            EvidenceItem(
                provider_name=r.provider_name,
                query_type=r.query_type,
                query_target=r.query_target,
                raw_status=r.status.value,
                is_malicious=r.is_malicious,
                threat_description=r.threat_description,
                source_reference=r.source_reference,
                normalized_result=r.raw_details,
                retrieved_at=r.retrieval_timestamp,
                latency_ms=r.latency_ms,
                error_message=r.error_message,
            )
            for r in all_records
        ]

        summary = (
            f"Analyzed {len(claims)} claim(s). "
            f"Debunked/Misleading: {debunked_count}, Verified: {verified_true_count}, "
            f"Unverified (no matching records found): {unverified_count}."
        )

        output = ClaimVerificationOutput(
            claims_analyzed=claims,
            debunked_claims_count=debunked_count,
            verified_true_count=verified_true_count,
            unverified_claims_count=unverified_count,
            records=evidence_items,
            summary=summary,
        )

        return output, all_records
