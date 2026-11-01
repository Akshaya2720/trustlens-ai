"""TrustLens AI - Agent D: Threat Intelligence

Orchestrates live concurrent queries across external threat reputation services:
VirusTotal, URLhaus, and PhishTank, combined with DNS/domain structural analysis
and restricted redirect-chain inspections.
"""

import asyncio
from typing import Any, Dict, List
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.clients.threat_intel.phishtank import PhishTankClient
from app.clients.threat_intel.urlhaus import URLhausClient
from app.clients.threat_intel.virustotal import VirusTotalClient
from app.schemas.agent_outputs import ThreatIntelligenceOutput
from app.schemas.evidence import EvidenceItem
from app.services.safe_url import SafeURLInspector


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
                    provider_consensus="clean",
                    summary="No URLs were provided or extracted for threat intelligence inspection.",
                ),
                [],
            )

        # 1. Structural domain inspection for each URL
        domain_analyses: Dict[str, Any] = {}
        redirect_analyses: Dict[str, Any] = {}

        for u in urls[:5]:
            try:
                domain_analyses[u] = SafeURLInspector.extract_domain_details(u)
            except Exception as e:
                domain_analyses[u] = {"error": str(e)}

        # Perform safe redirect preview on the first primary URL
        primary_url = urls[0]
        try:
            val_res = SafeURLInspector.validate_url(primary_url)
            if val_res.is_safe:
                redirect_res = await SafeURLInspector.fetch_head_or_preview(primary_url)
                redirect_analyses[primary_url] = redirect_res
            else:
                redirect_analyses[primary_url] = {"blocked_ssrf": True, "reason": val_res.reason}
        except Exception as e:
            redirect_analyses[primary_url] = {"error": str(e)}

        # 2. Query external threat intelligence providers concurrently
        url_tasks = [self.investigate_url(u) for u in urls[:5]]  # cap at first 5 URLs for safety/rate limits
        url_results = await asyncio.gather(*url_tasks)

        for rec_list in url_results:
            all_records.extend(rec_list)

        any_malicious = any(r.is_malicious for r in all_records)
        is_phishing = any(r.is_phishing for r in all_records)
        is_malware = any(r.is_malware for r in all_records)

        # 3. Provider consensus and disagreement analysis
        disagreements: List[str] = []
        malicious_by_url: Dict[str, List[str]] = {}
        clean_by_url: Dict[str, List[str]] = {}
        unavailable_by_url: Dict[str, List[str]] = {}

        for r in all_records:
            target = r.query_target
            if r.is_malicious:
                malicious_by_url.setdefault(target, []).append(r.provider_name)
            elif r.status in (ProviderStatus.OK, ProviderStatus.NO_MATCH):
                clean_by_url.setdefault(target, []).append(r.provider_name)
            else:
                unavailable_by_url.setdefault(target, []).append(r.provider_name)

        for u in urls[:5]:
            m_provs = malicious_by_url.get(u, [])
            c_provs = clean_by_url.get(u, [])
            if m_provs and c_provs:
                disagreement_msg = (
                    f"Provider disagreement for {u}: {', '.join(m_provs)} flagged malicious, "
                    f"while {', '.join(c_provs)} reported clean / unlisted."
                )
                disagreements.append(disagreement_msg)

        # Determine overall consensus
        total_responding = len([r for r in all_records if r.status in (ProviderStatus.OK, ProviderStatus.CONFIRMED_MATCH, ProviderStatus.NO_MATCH)])
        if is_malware:
            consensus = "confirmed_malware"
        elif is_phishing:
            consensus = "confirmed_phishing"
        elif any_malicious and disagreements:
            consensus = "disagreement"
        elif any_malicious:
            consensus = "malicious"
        elif total_responding > 0 and not any_malicious:
            consensus = "clean"
        else:
            consensus = "unknown"

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
            if disagreements:
                summary_parts.append(f"Note: {len(disagreements)} provider disagreement(s) recorded.")
        else:
            if consensus == "clean":
                summary_parts.append(
                    f"Completed {len(all_records)} threat intelligence query(ies) across {len(urls)} target(s). "
                    "Queried reputation providers returned clean records (unlisted does not guarantee absence of zero-day threats)."
                )
            else:
                summary_parts.append(
                    f"Completed {len(all_records)} query(ies) across {len(urls)} target(s). "
                    "Reputation status remains unknown or unavailable from external providers."
                )

        output = ThreatIntelligenceOutput(
            checked_urls=urls,
            records=evidence_items,
            any_malicious_detected=any_malicious,
            phishing_detected=is_phishing,
            malware_detected=is_malware,
            provider_consensus=consensus,
            provider_disagreements=disagreements,
            domain_analysis=domain_analyses,
            redirect_analysis=redirect_analyses,
            summary=" ".join(summary_parts),
        )

        return output, all_records
