"""TrustLens AI - Agent F: Risk Synthesis

Combines specialist agent findings, resolves contradictions, produces model explanations,
and integrates with the Deterministic Risk Engine.
"""

from typing import Any, Dict, List, Optional
from app.clients.meta_client import meta_client
from app.clients.threat_intel.base import NormalizedEvidenceRecord
from app.core.logging import logger
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ContentIntelligenceOutput,
    ImpersonationAnalysisOutput,
    RiskSynthesisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.schemas.evidence import RiskAssessmentSchema
from app.services.risk_engine import DeterministicRiskEngine


class RiskSynthesisAgent:
    """Agent F: Risk Synthesis."""

    SYSTEM_PROMPT = (
        "You are Agent F (Risk Synthesis) for TrustLens AI.\n"
        "Your duty is to synthesize all specialist findings into a cohesive, auditable explanation.\n"
        "You must:\n"
        "1. Identify agreement and disagreement between external evidence and message wording.\n"
        "2. Separate observable facts (exact phrases, HTTP codes, domain names) from interpretations.\n"
        "3. Explicitly state any unavailable services or missing evidence.\n"
        "4. Provide clear, non-technical safety recommendations for the user.\n"
        "CRITICAL: Do NOT invent findings or fabricate safety certitudes. If evidence is inconclusive, state so clearly."
    )

    @classmethod
    async def synthesize(
        cls,
        content_intel: ContentIntelligenceOutput,
        threat_intel: Optional[ThreatIntelligenceOutput] = None,
        scam_detection: Optional[ScamDetectionOutput] = None,
        impersonation: Optional[ImpersonationAnalysisOutput] = None,
        claim_verification: Optional[ClaimVerificationOutput] = None,
        evidence_records: Optional[List[NormalizedEvidenceRecord]] = None,
        provider_statuses: Optional[Dict[str, str]] = None,
    ) -> tuple[RiskSynthesisOutput, RiskAssessmentSchema]:
        # Step 1: Run deterministic risk engine first to calculate ground truth risk level & score
        assessment = DeterministicRiskEngine.calculate_risk(
            threat_intel=threat_intel,
            scam_detection=scam_detection,
            impersonation=impersonation,
            claim_verification=claim_verification,
            evidence_records=evidence_records,
            provider_statuses=provider_statuses,
        )

        # Baseline synthesis output
        agreements = []
        if threat_intel and threat_intel.any_malicious_detected:
            agreements.append("Threat intelligence confirms malicious destination identified in message content.")
        if scam_detection and scam_detection.credential_or_otp_harvesting:
            agreements.append("Observed explicit credential or OTP harvesting demand.")
        if impersonation and impersonation.is_domain_mismatch:
            agreements.append("Identified brand impersonation and domain mismatch.")

        baseline_explanation = (
            f"TrustLens automated analysis concluded a {assessment.risk_level.upper()} risk rating "
            f"(Score: {assessment.risk_score}/100, Confidence: {int(assessment.confidence * 100)}%). "
            f"Key observations: {'; '.join(assessment.indicators) if assessment.indicators else 'No critical threats flagged.'}"
        )

        synthesis_output = RiskSynthesisOutput(
            agreement_observations=agreements,
            contradictions=assessment.contradictions,
            missing_evidence=assessment.limitations,
            model_explanation=baseline_explanation,
            recommended_actions=assessment.recommendations,
        )

        # Step 2: If Meta Model API is configured, generate rich narrative explanation
        if meta_client.is_configured:
            prompt_summary = (
                f"Synthesize the following investigation data:\n"
                f"- Deterministic Risk Level: {assessment.risk_level}\n"
                f"- Deterministic Risk Score: {assessment.risk_score}/100\n"
                f"- Indicators: {assessment.indicators}\n"
                f"- Contradictions: {assessment.contradictions}\n"
                f"- Limitations: {assessment.limitations}\n"
                f"- Threat Intel Summary: {threat_intel.summary if threat_intel else 'N/A'}\n"
                f"- Scam Detection Reasoning: {scam_detection.reasoning if scam_detection else 'N/A'}\n"
                f"- Impersonation: {impersonation.inconsistencies if impersonation else 'N/A'}\n"
                f"- Claim Verification: {claim_verification.summary if claim_verification else 'N/A'}\n"
            )

            messages = [
                {"role": "system", "content": cls.SYSTEM_PROMPT},
                {"role": "user", "content": prompt_summary},
            ]

            try:
                gen_output, _ = await meta_client.generate_structured(
                    messages=messages,
                    schema=RiskSynthesisOutput,
                    temperature=0.2,
                )
                # Keep deterministic contradictions, missing evidence, and recommendations
                if assessment.contradictions:
                    for c in assessment.contradictions:
                        if c not in gen_output.contradictions:
                            gen_output.contradictions.append(c)
                if assessment.limitations:
                    for lim in assessment.limitations:
                        if lim not in gen_output.missing_evidence:
                            gen_output.missing_evidence.append(lim)
                if assessment.recommendations:
                    gen_output.recommended_actions = assessment.recommendations

                return gen_output, assessment
            except Exception as e:
                logger.warning(f"Agent F structured synthesis error: {e}. Utilizing baseline synthesis.")

        return synthesis_output, assessment
