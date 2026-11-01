"""TrustLens AI - Deterministic Risk Engine (Ruleset v1.2.0)

Deterministic, transparent scoring engine that aggregates evidence from
threat intelligence, fact-checking, social-engineering indicators, and domain consistency.
The language model never unilaterally assigns the final risk score.
"""

from typing import Any, Dict, List, Optional
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.schemas.evidence import RiskAssessmentSchema


class DeterministicRiskEngine:
    """Transparent, deterministic rule-based scoring engine for digital safety investigations."""

    RULESET_VERSION = "v1.4.0"

    # Base additive weights
    WEIGHT_CONFIRMED_MALWARE = 55.0
    WEIGHT_CONFIRMED_PHISHING = 55.0
    WEIGHT_VT_MALICIOUS_DETECTION = 40.0
    WEIGHT_DEBUNKED_FACTCHECK = 35.0
    WEIGHT_DOMAIN_IMPERSONATION = 35.0
    WEIGHT_CREDENTIAL_OTP_HARVESTING = 35.0
    WEIGHT_CROSS_MODAL_CONTRADICTION = 25.0
    WEIGHT_MULTI_CHANNEL_IMPERSONATION = 30.0
    WEIGHT_FINANCIAL_PRESSURE_URGENCY = 25.0
    WEIGHT_SUSPICIOUS_ATTACHMENT = 25.0

    # Risk Level Thresholds
    THRESHOLD_CRITICAL = 85.0
    THRESHOLD_HIGH = 60.0
    THRESHOLD_MEDIUM = 30.0

    @classmethod
    def calculate_risk(
        cls,
        threat_intel: Optional[ThreatIntelligenceOutput] = None,
        scam_detection: Optional[ScamDetectionOutput] = None,
        impersonation: Optional[ImpersonationAnalysisOutput] = None,
        claim_verification: Optional[ClaimVerificationOutput] = None,
        evidence_records: Optional[List[NormalizedEvidenceRecord]] = None,
        provider_statuses: Optional[Dict[str, str]] = None,
        discrepancies: Optional[List[str]] = None,
        ocr_confidence: Optional[float] = None,
        is_ocr_uncertain: bool = False,
    ) -> RiskAssessmentSchema:
        score = 0.0
        indicators: List[str] = []
        contradictions: List[str] = []
        recommendations: List[str] = []
        limitations: List[str] = []

        has_confirmed_malicious = False
        evidence_records = evidence_records or []
        provider_statuses = provider_statuses or {}
        discrepancies = discrepancies or []

        # 1. Threat Intelligence Rules
        if threat_intel:
            if threat_intel.malware_detected:
                score += cls.WEIGHT_CONFIRMED_MALWARE
                indicators.append("Verified malware hosting detected by threat intelligence sources.")
                has_confirmed_malicious = True

            if threat_intel.phishing_detected:
                score += cls.WEIGHT_CONFIRMED_PHISHING
                indicators.append("Verified phishing page record confirmed by threat intelligence databases.")
                has_confirmed_malicious = True

            if threat_intel.any_malicious_detected and not (threat_intel.malware_detected or threat_intel.phishing_detected):
                score += cls.WEIGHT_VT_MALICIOUS_DETECTION
                indicators.append("Multiple security engines flagged submitted URL as malicious.")
                has_confirmed_malicious = True

        # Check raw evidence records for external provider hits
        for ev in evidence_records:
            if ev.status == ProviderStatus.CONFIRMED_MATCH and ev.is_malicious:
                has_confirmed_malicious = True
                if ev.provider_name not in [i for i in indicators if ev.provider_name in i]:
                    indicators.append(f"{ev.provider_name} confirmed threat: {ev.threat_description or 'Malicious indicator'}")

        # 2. Impersonation & Identity Inconsistencies
        if impersonation:
            if impersonation.is_domain_mismatch:
                score += cls.WEIGHT_DOMAIN_IMPERSONATION
                indicators.append(
                    f"Brand/Domain mismatch: Content claims to represent '{impersonation.claimed_organization}' "
                    f"but sender or link targets '{impersonation.sender_domain_or_address}'."
                )
            if impersonation.brand_spoofing_indicators:
                for b_ind in impersonation.brand_spoofing_indicators:
                    indicators.append(f"Impersonation indicator: {b_ind}")

        # 3. Scam Detection Indicators (Observable Features)
        if scam_detection:
            if scam_detection.credential_or_otp_harvesting:
                score += cls.WEIGHT_CREDENTIAL_OTP_HARVESTING
                indicators.append("Observable credential or one-time password (OTP) harvesting pattern identified.")

            if scam_detection.financial_demands and scam_detection.urgency_detected:
                score += cls.WEIGHT_FINANCIAL_PRESSURE_URGENCY
                indicators.append("Coercive high-pressure timeline paired with financial transfer requests.")
            elif scam_detection.urgency_detected:
                score += 10.0
                indicators.append("Artificial urgency or threat of immediate account suspension.")

            if scam_detection.threat_or_reward_patterns:
                for p in scam_detection.threat_or_reward_patterns:
                    if "arrest warrant" in p or "legal action" in p:
                        score += 35.0
                        indicators.append("Coercive extortion threat: False threat of law enforcement or arrest warrant.")
                    elif "family emergency" in p:
                        score += 35.0
                        indicators.append("High-risk family emergency social engineering lure ('dropped phone' impersonation).")
                    else:
                        indicators.append(f"Pattern: {p}")

        # Check for suspicious direct binary or executable downloads or raw IP host in checked URLs
        if threat_intel and threat_intel.checked_urls:
            for u in threat_intel.checked_urls:
                lower_u = u.lower()
                has_exec = any(ext in lower_u for ext in [".exe", ".bin", ".scr", ".bat", ".apk", ".dmg", ".vbs"])
                if has_exec:
                    score += cls.WEIGHT_SUSPICIOUS_ATTACHMENT
                    indicators.append(f"Suspicious executable or script payload URL detected: {u}")

                # Check if URL host is a raw IP address (common in malicious payload servers)
                import re
                if re.search(r"://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", lower_u):
                    score += 20.0
                    indicators.append(f"URL uses raw IP address instead of domain hostname ({u}).")
                    if has_exec:
                        score += 20.0
                        indicators.append("High-severity combination: Direct executable binary hosted on raw unindexed IP address.")

            # Structural Domain & Subdomain Deception
            if threat_intel.domain_analysis:
                for u, da in threat_intel.domain_analysis.items():
                    if isinstance(da, dict):
                        if da.get("subdomain_brand_deception"):
                            score += cls.WEIGHT_DOMAIN_IMPERSONATION
                            brands = ", ".join(da.get("deceptive_brands_found", []))
                            indicators.append(
                                f"Deceptive Subdomain Impersonation: Target brand(s) '{brands}' detected in subdomain "
                                f"of unrelated root domain '{da.get('root_domain')}'."
                            )
                        if da.get("has_high_risk_tld") and (da.get("sensitive_path_keywords") or da.get("subdomain_brand_deception")):
                            score += 15.0
                            indicators.append(f"Abuse-prone TLD (.{da.get('tld')}) paired with sensitive credential keywords.")

            # Redirect Chain Inspection
            if threat_intel.redirect_analysis:
                for u, ra in threat_intel.redirect_analysis.items():
                    if isinstance(ra, dict):
                        if ra.get("is_cross_domain_redirect"):
                            score += 20.0
                            indicators.append(f"Cross-Domain Redirect: {ra.get('initial_url')} redirects across domain boundaries to {ra.get('final_url')}.")

            # Provider Disagreements
            if threat_intel.provider_disagreements:
                for d in threat_intel.provider_disagreements:
                    contradictions.append(f"Threat Intelligence Disagreement: {d}")



        # 4. Claim Verification (Fact Checking)
        if claim_verification:
            if claim_verification.debunked_claims_count > 0:
                score += cls.WEIGHT_DEBUNKED_FACTCHECK
                indicators.append(
                    f"Independent fact-checking sources have debunked {claim_verification.debunked_claims_count} claim(s) as false or misleading."
                )
            if claim_verification.verified_true_count > 0:
                score = max(0.0, score - 20.0)
                indicators.append(
                    f"Verified authentic: {claim_verification.verified_true_count} claim(s) confirmed by authoritative sources."
                )
            if claim_verification.unverified_claims_count > 0:
                limitations.append(
                    f"{claim_verification.unverified_claims_count} claim(s) lack authoritative third-party fact-checking records and remain unverified."
                )

        # 5. Contradiction Detection & Discrepancies
        for d in discrepancies:
            contradictions.append(f"Model-OCR Extraction Discrepancy: {d}")
            indicators.append(f"Observable Extraction Inconsistency: {d}")

        has_cross_modal_contradiction = False
        has_multi_channel_impersonation = False
        for c in contradictions:
            if "Cross-Modal Contradiction" in c:
                has_cross_modal_contradiction = True
                score += cls.WEIGHT_CROSS_MODAL_CONTRADICTION
                indicators.append(f"High-Risk Cross-Modal Inconsistency: {c}")
            elif "Multi-channel" in c or "multi-channel" in c:
                has_multi_channel_impersonation = True
                score += cls.WEIGHT_MULTI_CHANNEL_IMPERSONATION
                indicators.append(f"Coordinated Multi-Channel Impersonation: {c}")

        # Check if URL reputation is clean but scam text is aggressive
        clean_url_providers = [
            ev.provider_name for ev in evidence_records
            if ev.query_type == "url" and ev.status == ProviderStatus.OK and not ev.is_malicious
        ]
        if clean_url_providers and scam_detection and scam_detection.credential_or_otp_harvesting:
            contradictions.append(
                f"Threat intelligence providers ({', '.join(clean_url_providers)}) report no existing malware/phishing records, "
                "yet the text exhibits clear credential-harvesting patterns (suggests brand new zero-day phishing or unindexed lure)."
            )

        # 6. Cap and Floor Logic
        # Rule: A confirmed malicious record strictly prevents risk from dropping below HIGH (min 70 score)
        if has_confirmed_malicious:
            score = max(score, 70.0)

        # Rule: A debunked false claim strictly prevents risk from dropping below HIGH (min 65 score)
        if claim_verification and claim_verification.debunked_claims_count > 0:
            score = max(score, 65.0)

        # Rule: Cross-modal contradiction strictly enforces minimum HIGH risk (min 65 score)
        if has_cross_modal_contradiction:
            score = max(score, 65.0)

        # Rule: Active credential/OTP harvesting paired with urgency enforces min 60 score
        if scam_detection and scam_detection.credential_or_otp_harvesting and scam_detection.urgency_detected:
            score = max(score, 60.0)

        # Normalize score within [0, 100]
        score = min(100.0, max(0.0, score))

        # 7. Limitations & OCR Uncertainty Tracking
        if is_ocr_uncertain or (ocr_confidence is not None and ocr_confidence < 0.5):
            conf_str = f"{ocr_confidence:.2f}" if ocr_confidence is not None else "uncertain"
            limitations.append(
                f"OCR text extraction had low confidence ({conf_str}); image may contain noisy, rotated, or low-resolution text."
            )

        for prov_name, st in provider_statuses.items():
            if st == ProviderStatus.NOT_CONFIGURED.value:
                limitations.append(f"{prov_name} API is not configured; check was bypassed.")
            elif st in (ProviderStatus.UNAVAILABLE.value, ProviderStatus.ERROR.value):
                limitations.append(f"{prov_name} service was temporarily unreachable or returned an error.")
            elif st == ProviderStatus.RATE_LIMITED.value:
                limitations.append(f"{prov_name} query was skipped due to rate limiting.")

        # 8. Determine Risk Level
        total_checks = len(evidence_records) + (1 if scam_detection else 0) + (1 if impersonation else 0) + (1 if claim_verification else 0)
        successful_checks = len([ev for ev in evidence_records if ev.status in (ProviderStatus.OK, ProviderStatus.CONFIRMED_MATCH, ProviderStatus.NO_MATCH)])
        if scam_detection:
            successful_checks += 1
        if impersonation:
            successful_checks += 1
        if claim_verification:
            successful_checks += 1

        evidence_coverage = (successful_checks / max(1, total_checks))

        # Check if this investigation evaluates URLs
        is_url_eval = any(ev.query_type == "url" for ev in evidence_records) or (threat_intel and bool(threat_intel.checked_urls))
        has_any_verified_url_check = any(ev.query_type == "url" and ev.status in (ProviderStatus.OK, ProviderStatus.CONFIRMED_MATCH, ProviderStatus.NO_MATCH) for ev in evidence_records)
        unverified_url_investigation = is_url_eval and not has_any_verified_url_check

        if unverified_url_investigation:
            limitations.append("URL reputation could not be verified by external threat providers. An unlisted or unknown URL cannot be classified as safe.")

        if score >= cls.THRESHOLD_CRITICAL:
            risk_level = "critical"
        elif score >= cls.THRESHOLD_HIGH:
            risk_level = "high"
        elif score >= cls.THRESHOLD_MEDIUM:
            risk_level = "medium"
        elif total_checks > 0 and score < cls.THRESHOLD_MEDIUM and not has_confirmed_malicious and not unverified_url_investigation:
            # Low risk requires clean checks without ambiguity or unverified status
            risk_level = "low"
        else:
            risk_level = "unknown"

        # 9. Confidence Calculation
        # Calibrated strictly based on corroborated evidence count and source coverage
        base_conf = 0.5
        if has_confirmed_malicious:
            base_conf = 0.90
        elif risk_level == "low" and successful_checks >= 2:
            base_conf = 0.85
        elif risk_level == "medium":
            base_conf = 0.70

        if is_ocr_uncertain and not has_confirmed_malicious:
            base_conf = max(0.3, base_conf * 0.85)

        confidence = round(min(1.0, base_conf * evidence_coverage), 2)

        # 10. Recommended Next Steps
        if risk_level in ("high", "critical"):
            recommendations.append("DO NOT click any links, open attachments, or scan QR codes provided in this message.")
            recommendations.append("DO NOT provide passwords, verification codes, OTPs, or banking details.")
            recommendations.append("Report and block the sender on your email or messaging client.")
            if impersonation and impersonation.claimed_organization:
                recommendations.append(
                    f"If you need to contact {impersonation.claimed_organization}, do so exclusively via their official website or verified customer service number."
                )
        elif risk_level == "medium":
            recommendations.append("Exercise caution. Verify the sender's identity through a separate, known channel before responding.")
            recommendations.append("Inspect links manually and check domain spelling before entering any credentials.")
        elif risk_level == "low":
            recommendations.append("No active malicious indicators detected across inspected sources. Maintain standard digital safety practices.")
        else:
            recommendations.append("Evidence is insufficient or inconclusive. Treat content with caution until identity can be verified independently.")

        return RiskAssessmentSchema(
            risk_level=risk_level,
            risk_score=round(score, 1),
            confidence=confidence,
            indicators=indicators,
            contradictions=contradictions,
            recommendations=recommendations,
            limitations=limitations,
        )
