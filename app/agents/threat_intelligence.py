"""TrustLens AI - Agent D: Threat Intelligence

Orchestrates live concurrent queries across external threat reputation services:
VirusTotal, URLhaus, and PhishTank.
"""

import asyncio
from typing import List
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.clients.threat_intel.phishtank import PhishTankClient
from app.clients.threat_intel.urlhaus import URLhausClient
from app.clients.threat_intel.virustotal import VirusTotalClient
from app.schemas.agent_outputs import ThreatIntelligenceOutput
from app.schemas.evidence import EvidenceItem


class ThreatIntelligenceAgent:
    """Agent D: Threat Intelligence."""

    def __init__(self):
        self.vt_client = VirusTotalClient()
        self.urlhaus_client = URLhausClient()
        self.phishtank_client = PhishTankClient()

    async def investigate_url(self, url: str) -> List[NormalizedEvidenceRecord]:
        """Queries VirusTotal, URLhaus, and PhishTank concurrently for a given URL."""
        tasks = [
            self.vt_client.check_url(url),
            self.urlhaus_client.check_url(url),
            self.phishtank_client.check_url(url),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        records: List[NormalizedEvidenceRecord] = []
        for r in results:
            if isinstance(r, NormalizedEvidenceRecord):
                records.append(r)
            elif isinstance(r, Exception):
                records.append(
                    NormalizedEvidenceRecord(
                        provider_name="UnknownThreatProvider",
                        query_type="url",
                        query_target=url,
                        status=ProviderStatus.ERROR,
                        error_message=str(r),
                    )
                )
        return records

    async def analyze(self, urls: List[str]) -> tuple[ThreatIntelligenceOutput, List[NormalizedEvidenceRecord]]:
        all_records: List[NormalizedEvidenceRecord] = []
        if not urls:
            return (
                ThreatIntelligenceOutput(
                    checked_urls=[],
                    records=[],
                    any_malicious_detected=False,
                    summary="No URLs were provided or extracted for threat intelligence inspection.",
                ),
                [],
            )

        # Investigate all URLs concurrently
        url_tasks = [self.investigate_url(u) for u in urls[:5]]  # cap at first 5 URLs for safety/rate limits
        url_results = await asyncio.gather(*url_tasks)

        for rec_list in url_results:
            all_records.extend(rec_list)

        any_malicious = any(r.is_malicious for r in all_records)
        is_phishing = any(r.is_phishing for r in all_records)
        is_malware = any(r.is_malware for r in all_records)

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

        summary_parts = []
        if any_malicious:
            summary_parts.append(f"Threat detected! Malicious indicators confirmed across {len([r for r in all_records if r.is_malicious])} check(s).")
            if is_phishing:
                summary_parts.append("Phishing database match confirmed.")
            if is_malware:
                summary_parts.append("Malware payload distribution match confirmed.")
        else:
            summary_parts.append(
                f"Completed {len(all_records)} threat intelligence query(ies) across {len(urls)} target(s). "
                "No active malicious detections found in inspected databases (unlisted does not guarantee safety)."
            )

        output = ThreatIntelligenceOutput(
            checked_urls=urls,
            records=evidence_items,
            any_malicious_detected=any_malicious,
            phishing_detected=is_phishing,
            malware_detected=is_malware,
            summary=" ".join(summary_parts),
        )

        return output, all_records
