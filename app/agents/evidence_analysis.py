"""TrustLens AI - Agent 6: Evidence Analysis Agent

Reconciles findings across specialist agents (Threat Intelligence, Scam Detection,
Impersonation Analysis, and Claim Verification). Identifies cross-modal corroboration,
flags contradictions, highlights missing evidence, calculates evidence coverage,
and isolates uncertainties before final risk synthesis.
"""

from typing import Any, Dict, List, Optional
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.logging import logger
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ContentIntelligenceOutput,
    EvidenceAnalysisOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)


class EvidenceAnalysisAgent:
    """Agent 6: Evidence Analysis Agent."""

    @classmethod
    async def analyze(
        cls,
        content_intel: ContentIntelligenceOutput,
        threat_intel: Optional[ThreatIntelligenceOutput] = None,
        scam_detection: Optional[ScamDetectionOutput] = None,
        impersonation: Optional[ImpersonationAnalysisOutput] = None,
        claim_verification: Optional[ClaimVerificationOutput] = None,
        evidence_records: Optional[List[NormalizedEvidenceRecord]] = None,
        provider_statuses: Optional[Dict[str, str]] = None,
        discrepancies: Optional[List[str]] = None,
        ocr_confidence: Optional[float] = None,
        is_ocr_uncertain: bool = False,
        planned_tools: Optional[List[str]] = None,
    ) -> EvidenceAnalysisOutput:
        """Reconciles evidentiary streams across all agents."""
        logger.info("Executing Agent 6: Evidence Analysis")
        evidence_records = evidence_records or []
        provider_statuses = provider_statuses or {}
        discrepancies = discrepancies or []
        planned_tools = planned_tools or []

        corroborations: List[str] = []
        contradictions: List[str] = []
        missing_evidence: List[str] = []
        uncertainties: List[str] = []

        # 1. Evaluate Corroboration
        if threat_intel and threat_intel.any_malicious_detected:
            if scam_detection and (scam_detection.credential_or_otp_harvesting or scam_detection.urgency_detected):
                corroborations.append(
                    "Threat intelligence confirming malicious infrastructure corroborates scam detection of credential/urgency pressure."
                )
            if impersonation and impersonation.is_domain_mismatch:
                corroborations.append(
                    "External threat intelligence malicious flags corroborate brand domain spoofing detection."
                )

        if claim_verification and claim_verification.debunked_claims_count > 0:
            if scam_detection and scam_detection.financial_demands:
                corroborations.append(
                    "Authoritative fact-checking confirming debunked public claim corroborates financial fraud lure."
                )

        # Multi-provider consensus
        if threat_intel and threat_intel.provider_consensus in ("confirmed_phishing", "confirmed_malware"):
            corroborations.append(
                f"Multi-provider consensus achieved ({threat_intel.provider_consensus}) across queried security databases."
            )

        # 2. Evaluate Contradictions
        if impersonation and impersonation.is_domain_mismatch:
            for inc in impersonation.inconsistencies:
                contradictions.append(inc)

        if threat_intel and threat_intel.provider_disagreements:
            for dis in threat_intel.provider_disagreements:
                contradictions.append(f"Security provider verdict conflict: {dis}")

        for disc in discrepancies:
            if "discrepancy" in disc.lower() or "conflict" in disc.lower() or "mismatch" in disc.lower():
                contradictions.append(disc)

        # 3. Evaluate Missing Evidence & Coverage
        total_checks = 0
        completed_checks = 0

        for provider, status_val in provider_statuses.items():
            total_checks += 1
            if status_val in (ProviderStatus.OK.value, ProviderStatus.CONFIRMED_MATCH.value, ProviderStatus.NO_MATCH.value):
                completed_checks += 1
            elif status_val == ProviderStatus.NOT_CONFIGURED.value:
                missing_evidence.append(f"Threat provider '{provider}' is unconfigured; checks were skipped.")
            elif status_val == ProviderStatus.UNAVAILABLE.value:
                missing_evidence.append(f"Threat provider '{provider}' is unavailable or timed out.")
            elif status_val == ProviderStatus.RATE_LIMITED.value:
                missing_evidence.append(f"Threat provider '{provider}' rate limit exceeded.")

        if claim_verification and claim_verification.unverified_claims_count > 0:
            missing_evidence.append(
                f"{claim_verification.unverified_claims_count} extracted claim(s) lacked third-party fact-checking records."
            )

        # Check planned tools completion
        for tool in planned_tools:
            if tool == "threat_intel" and not threat_intel:
                missing_evidence.append("Threat intelligence check was scheduled but yielded no output.")
            elif tool == "claim_verification" and not claim_verification:
                missing_evidence.append("Claim verification check was scheduled but yielded no output.")

        coverage_ratio = (completed_checks / total_checks) if total_checks > 0 else 1.0
        coverage_ratio = max(0.0, min(1.0, round(coverage_ratio, 2)))

        # 4. Evaluate Uncertainties
        if is_ocr_uncertain or (ocr_confidence is not None and ocr_confidence < 0.60):
            uncertainties.append(
                f"OCR visual text extraction has low confidence ({ocr_confidence or 'unknown'}), indicating potential character misreadings."
            )

        if threat_intel and threat_intel.provider_consensus == "unknown":
            uncertainties.append(
                "Destination URL reputation remains unverified across queried threat databases."
            )

        if claim_verification and claim_verification.unverified_claims_count > 0:
            uncertainties.append(
                "Factual assertions could not be confirmed or refuted from public repositories."
            )

        # 5. Objective Summary
        summary_parts = []
        if corroborations:
            summary_parts.append(f"{len(corroborations)} corroborated evidentiary point(s)")
        if contradictions:
            summary_parts.append(f"{len(contradictions)} contradiction(s)")
        if missing_evidence:
            summary_parts.append(f"{len(missing_evidence)} data gap(s)")
        if uncertainties:
            summary_parts.append(f"{len(uncertainties)} uncertainty factor(s)")

        summary = (
            f"Evidence Analysis reconciled findings with {int(coverage_ratio * 100)}% coverage: "
            + (", ".join(summary_parts) if summary_parts else "all findings consistent with baseline checks.")
        )

        return EvidenceAnalysisOutput(
            corroborating_evidence=corroborations,
            contradictions=contradictions,
            missing_evidence=missing_evidence,
            uncertainties=uncertainties,
            evidence_coverage_ratio=coverage_ratio,
            summary=summary,
        )
