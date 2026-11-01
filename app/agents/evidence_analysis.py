"""TrustLens AI - Agent 6: Evidence Analysis Agent

Reconciles findings across specialist agents (Threat Intelligence, Scam Detection,
Impersonation Analysis, and Claim Verification) and modalities (Text, Screenshot/OCR,
Audio/Voice Note, and URL Network Infrastructure).
Identifies cross-modal corroboration, flags cross-modal contradictions, highlights
missing evidence, calculates evidence coverage, and isolates uncertainties.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
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


KNOWN_BRAND_KEYWORDS = [
    "paypal", "apple", "irs", "amazon", "chase", "bank of america",
    "wells fargo", "netflix", "microsoft", "google", "meta", "facebook",
    "instagram", "usps", "fedex", "dhl",
]


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
        image_analysis: Optional[Dict[str, Any]] = None,
        audio_analysis: Optional[Dict[str, Any]] = None,
        raw_text: Optional[str] = None,
        extracted_urls: Optional[List[str]] = None,
    ) -> EvidenceAnalysisOutput:
        """Reconciles evidentiary streams across all agents and modalities."""
        logger.info("Executing Agent 6: Evidence Analysis")
        evidence_records = evidence_records or []
        provider_statuses = provider_statuses or {}
        discrepancies = discrepancies or []
        planned_tools = planned_tools or []
        extracted_urls = extracted_urls or []
        raw_text_lower = (raw_text or "").lower()

        corroborations: List[str] = []
        contradictions: List[str] = []
        missing_evidence: List[str] = []
        uncertainties: List[str] = []

        # -------------------------------------------------------------
        # 1. Multi-Agent Security Corroborations
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # 2. Cross-Modal Engine: Corroboration & Contradictions
        # -------------------------------------------------------------
        # Detect claimed brands across modalities
        claimed_brands_by_modality: Dict[str, str] = {}

        # Modality: Text
        if impersonation and impersonation.claimed_organization:
            claimed_brands_by_modality["text"] = impersonation.claimed_organization.lower()
        else:
            for b in KNOWN_BRAND_KEYWORDS:
                if b in raw_text_lower:
                    claimed_brands_by_modality["text"] = b
                    break

        # Modality: Image / Screenshot
        if image_analysis:
            img_org = image_analysis.get("primary_organization") or image_analysis.get("claimed_sender_or_organization")
            if img_org:
                claimed_brands_by_modality["image"] = str(img_org).lower()

        # Modality: Audio
        if audio_analysis:
            audio_auth = audio_analysis.get("claims_of_authority") or []
            audio_text = (audio_analysis.get("full_transcript") or "").lower()
            for b in KNOWN_BRAND_KEYWORDS + ["police", "fbi", "court", "marshals"]:
                if any(b in str(a).lower() for a in audio_auth) or b in audio_text:
                    claimed_brands_by_modality["audio"] = b
                    break

        # Check brand consistency across submitted modalities
        active_modalities = list(claimed_brands_by_modality.keys())
        if len(active_modalities) >= 2:
            unique_brands = set(claimed_brands_by_modality.values())
            if len(unique_brands) == 1:
                brand_name = list(unique_brands)[0].title()
                if threat_intel and threat_intel.any_malicious_detected:
                    corroborations.append(
                        f"Cross-Modal Corroboration: Multi-channel campaign detected where {' and '.join(active_modalities)} elements align on claiming '{brand_name}' while network link directs to external threat infrastructure."
                    )
                else:
                    corroborations.append(
                        f"Cross-Modal Corroboration: Multiple modalities ({', '.join(active_modalities)}) consistently reference '{brand_name}'."
                    )
            else:
                modality_details = [f"{m}: '{claimed_brands_by_modality[m].title()}'" for m in active_modalities]
                contradictions.append(
                    f"Cross-Modal Contradiction (Organization Inconsistency): Conflicting institutional claims across modalities ({'; '.join(modality_details)})."
                )

        # Cross-Modal: Text URL vs Image Screenshot URL
        if image_analysis:
            img_urls = image_analysis.get("all_urls") or image_analysis.get("visible_urls") or []
            text_urls = [u for u in extracted_urls if u not in img_urls]
            if img_urls and text_urls:
                text_hosts = {urlparse(u).hostname for u in text_urls if urlparse(u).hostname}
                img_hosts = {urlparse(u).hostname for u in img_urls if urlparse(u).hostname}
                if text_hosts and img_hosts and text_hosts != img_hosts:
                    contradictions.append(
                        f"Cross-Modal Contradiction (Text vs Image URL): Message text specifies '{', '.join(filter(None, text_hosts))}' whereas screenshot displays different destination '{', '.join(filter(None, img_hosts))}'."
                    )

        # Cross-Modal: Audio Verbal Demands vs Network Destination
        if audio_analysis:
            audio_threats = audio_analysis.get("urgency_and_threats") or []
            audio_money = audio_analysis.get("financial_requests") or audio_analysis.get("requests_to_transfer_money") or []
            if audio_threats and not (threat_intel and threat_intel.any_malicious_detected) and not (scam_detection and scam_detection.credential_or_otp_harvesting):
                contradictions.append(
                    "Cross-Modal Discrepancy: High-pressure verbal coercion in voice recording is unsupported by technical domain findings."
                )
            if audio_money and extracted_urls:
                for u in extracted_urls:
                    if threat_intel and threat_intel.any_malicious_detected:
                        corroborations.append(
                            f"Cross-Modal Corroboration: Verbal financial demand in audio pairs with malicious URL destination '{u}'."
                        )

        # -------------------------------------------------------------
        # 3. Impersonation & Provider Disagreements
        # -------------------------------------------------------------
        if impersonation and impersonation.is_domain_mismatch:
            for inc in impersonation.inconsistencies:
                contradictions.append(inc)

        if threat_intel and threat_intel.provider_disagreements:
            for dis in threat_intel.provider_disagreements:
                contradictions.append(f"Security provider verdict conflict: {dis}")

        for disc in discrepancies:
            if any(k in disc.lower() for k in ("discrepancy", "conflict", "mismatch", "inconsistency")):
                if disc not in contradictions:
                    contradictions.append(disc)

        # -------------------------------------------------------------
        # 4. Missing Evidence & Evidence Coverage
        # -------------------------------------------------------------
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

        for tool in planned_tools:
            if tool == "threat_intel" and not threat_intel:
                missing_evidence.append("Threat intelligence check was scheduled but yielded no output.")
            elif tool == "claim_verification" and not claim_verification:
                missing_evidence.append("Claim verification check was scheduled but yielded no output.")

        coverage_ratio = (completed_checks / total_checks) if total_checks > 0 else 1.0
        coverage_ratio = max(0.0, min(1.0, round(coverage_ratio, 2)))

        # -------------------------------------------------------------
        # 5. Uncertainties & Limitations
        # -------------------------------------------------------------
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

        # -------------------------------------------------------------
        # 6. Objective Summary
        # -------------------------------------------------------------
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
            f"Evidence Analysis reconciled multimodal findings with {int(coverage_ratio * 100)}% coverage: "
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
