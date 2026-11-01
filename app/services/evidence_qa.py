"""TrustLens AI - Evidence-Grounded Q&A Service (Phase 9)

Provides grounded, factual responses to follow-up inquiries regarding completed investigations.
Ensures zero speculation, explicit citation of evidence IDs, and auditable disclaimers when
information was not part of the investigation record.
"""

import logging
import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.clients.meta_client import MetaModelClient
from app.db.models import Investigation

logger = logging.getLogger("trustlens.services.evidence_qa")


class GroundedQAOutput(BaseModel):
    """Structured response schema for evidence-grounded follow-up answers."""
    answer: str = Field(..., description="Direct factual answer to the inquiry grounded in evidence records.")
    referenced_evidence_ids: List[str] = Field(
        default_factory=list,
        description="IDs of external evidence records or artifact IDs cited in the answer."
    )
    confidence: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description="Confidence score calibrated against evidence coverage and certainty."
    )
    groundedness_assessment: str = Field(
        default="fully_grounded",
        description="Assessment: 'fully_grounded', 'partially_grounded', or 'unsupported'."
    )
    missing_information_notice: Optional[str] = Field(
        default=None,
        description="Explicit notice stating what information was not examined or absent in the investigation."
    )
    grounded_in_evidence: bool = Field(
        default=True,
        description="Whether the response is strictly supported by evidentiary records."
    )


class EvidenceQAService:
    """Service to synthesize strictly grounded answers from investigation artifacts and evidence."""

    @classmethod
    def build_evidentiary_context(cls, inv: Investigation) -> Dict[str, Any]:
        """Builds a structured dictionary and readable dossier of the investigation findings."""
        artifacts_summary = []
        for art in inv.artifacts or []:
            info = f"Artifact [ID: {art.id}] Type: {art.artifact_type}, Name: {art.filename or 'unnamed'}"
            if art.ocr_text:
                info += f"\n  OCR Text Extracted: {art.ocr_text[:500]}"
            if art.transcript:
                info += f"\n  Audio Transcript: {art.transcript[:500]}"
            artifacts_summary.append(info)

        evidence_records = []
        for ev in inv.external_evidence or []:
            rec = (
                f"[Evidence ID: {ev.id}] Provider: {ev.provider_name} | Target: {ev.query_target} | "
                f"Query Type: {ev.query_type} | Status: {ev.raw_status} | Malicious: {ev.is_malicious} | "
                f"Threat Description: {ev.threat_description or 'None'} | Source: {ev.source_reference or 'N/A'}"
            )
            evidence_records.append(rec)

        claims_records = []
        for clm in inv.claims or []:
            claims_records.append(
                f"Claim: '{clm.claim_text}' | Verification Status: {clm.verification_status} | "
                f"Source: {clm.source_reference or 'N/A'}"
            )

        if inv.risk_assessment:
            indicators = inv.risk_assessment.indicators or []
            contradictions = inv.risk_assessment.contradictions or []
            limitations = inv.risk_assessment.limitations or []
            recommendations = getattr(inv.risk_assessment, "recommendations", None) or getattr(inv.risk_assessment, "recommended_actions", []) or []
            breakdown = getattr(inv.risk_assessment, "score_breakdown", {}) or {}
        else:
            indicators, contradictions, limitations, recommendations, breakdown = [], [], [], [], {}

        dossier_text = (
            f"INVESTIGATION DOSSIER\n"
            f"Investigation ID: {inv.id}\n"
            f"Input Type: {inv.input_type}\n"
            f"Final Risk Level: {inv.final_risk_level.upper()} (Risk Score: {inv.final_risk_score}/100, Confidence: {inv.confidence})\n"
            f"Summary: {inv.summary or 'No summary recorded.'}\n\n"
            f"ARTIFACTS ({len(artifacts_summary)} items):\n"
            + ("\n".join(artifacts_summary) if artifacts_summary else "No stored artifacts.")
            + f"\n\nEXTERNAL EVIDENCE CHECKS ({len(evidence_records)} records):\n"
            + ("\n".join(evidence_records) if evidence_records else "No external evidence records.")
            + f"\n\nFACTUAL CLAIMS ({len(claims_records)} claims):\n"
            + ("\n".join(claims_records) if claims_records else "No claims extracted.")
            + f"\n\nRISK ASSESSMENT DETAILS:\n"
            + f"- Indicators: {indicators}\n"
            + f"- Contradictions: {contradictions}\n"
            + f"- Limitations: {limitations}\n"
            + f"- Recommendations: {recommendations}\n"
            + f"- Score Breakdown: {breakdown}\n"
        )

        return {
            "dossier_text": dossier_text,
            "artifacts": inv.artifacts or [],
            "external_evidence": inv.external_evidence or [],
            "claims": inv.claims or [],
            "indicators": indicators,
            "contradictions": contradictions,
            "limitations": limitations,
            "recommendations": recommendations,
        }

    @classmethod
    async def answer_question(
        cls,
        inv: Investigation,
        question: str,
        meta_client: MetaModelClient,
    ) -> GroundedQAOutput:
        """Answers a user inquiry with strict evidentiary grounding."""
        ctx = cls.build_evidentiary_context(inv)
        q_clean = question.strip()
        q_lower = q_clean.lower()

        # If Meta model is configured, try structured generation with strict grounding instructions
        if meta_client.is_configured:
            system_prompt = (
                "You are the TrustLens AI Evidence-Grounded Q&A Assistant.\n"
                "Your role is to answer questions about a completed digital threat investigation.\n"
                "MANDATORY CONSTRAINTS:\n"
                "1. STRICT GROUNDING: State ONLY facts explicitly recorded in the investigation dossier.\n"
                "2. NO SPECULATION: Never assume unperformed checks or invent sender identities, outcomes, or intent.\n"
                "3. CITATION: Whenever referring to a provider finding, reputation check, or URL result, you MUST include the exact evidence ID(s) in referenced_evidence_ids.\n"
                "4. ABSENT INFORMATION: If the user asks about an aspect that was NOT analyzed or is absent from the evidence (e.g. general trivia, unverified sender biography, unperformed scans), you MUST:\n"
                "   - Set missing_information_notice explaining what was not investigated\n"
                "   - Set groundedness_assessment to 'unsupported' or 'partially_grounded'\n"
                "   - Explicitly state in the answer: 'The requested information was not part of the evidence gathered during this investigation.'\n"
            )

            messages = [
                {"role": "system", "content": system_prompt},
                {
                    "role": "user",
                    "content": f"{ctx['dossier_text']}\n\nUSER QUESTION: {q_clean}",
                },
            ]

            try:
                resp = await meta_client.generate_structured(
                    messages=messages,
                    response_model=GroundedQAOutput,
                    temperature=0.1,
                )
                return resp
            except Exception as e:
                logger.warning(f"Meta QA model generation failed, falling back to deterministic QA engine: {e}")

        # Deterministic Grounded Q&A Fallback Engine
        return cls._deterministic_answer(inv, ctx, q_clean, q_lower)

    @classmethod
    def _deterministic_answer(
        cls,
        inv: Investigation,
        ctx: Dict[str, Any],
        question: str,
        q_lower: str,
    ) -> GroundedQAOutput:
        """Deterministic, rules-based evidence answering engine when LLM is unavailable or unconfigured."""
        all_ev = ctx["external_evidence"]
        all_art = ctx["artifacts"]
        all_claims = ctx["claims"]

        # 1. Question regarding Risk Level, Score, or Why the assessment was reached
        if any(w in q_lower for w in ["risk level", "score", "why", "assessment", "dangerous", "safe"]):
            referenced_ids = [ev.id for ev in all_ev if ev.is_malicious]
            indicators_str = "; ".join(ctx["indicators"]) if ctx["indicators"] else "No malicious indicators flagged."
            ans = (
                f"Investigation {inv.id} evaluated the input as {inv.final_risk_level.upper()} risk "
                f"with a final risk score of {inv.final_risk_score}/100 (confidence: {inv.confidence}). "
                f"Key contributing factors: {indicators_str}"
            )
            return GroundedQAOutput(
                answer=ans,
                referenced_evidence_ids=referenced_ids,
                confidence=min(1.0, max(0.7, inv.confidence)),
                groundedness_assessment="fully_grounded",
                missing_information_notice=None,
                grounded_in_evidence=True,
            )

        # 2. Question regarding URLs, Domains, Virustotal, or Phishing checks
        if any(w in q_lower for w in ["url", "domain", "link", "virustotal", "phishtank", "urlhaus", "malicious", "phish"]):
            url_ev = [ev for ev in all_ev if ev.query_type == "url" or "http" in (ev.query_target or "")]
            if url_ev:
                ref_ids = [ev.id for ev in url_ev]
                details = []
                for ev in url_ev:
                    status_lbl = "CONFIRMED MALICIOUS/PHISHING" if ev.is_malicious else f"Status: {ev.raw_status}"
                    details.append(f"{ev.provider_name} for '{ev.query_target}' returned: {status_lbl} ({ev.threat_description or 'clean/no match'})")
                ans = f"Threat intelligence checks were conducted on URLs found in this investigation:\n" + "\n".join(details)
                return GroundedQAOutput(
                    answer=ans,
                    referenced_evidence_ids=ref_ids,
                    confidence=0.95,
                    groundedness_assessment="fully_grounded",
                    missing_information_notice=None,
                    grounded_in_evidence=True,
                )
            else:
                return GroundedQAOutput(
                    answer="No URLs were detected or inspected in this investigation record.",
                    referenced_evidence_ids=[],
                    confidence=0.9,
                    groundedness_assessment="fully_grounded",
                    missing_information_notice="No URL extraction or threat intelligence checks were applicable to this submission.",
                    grounded_in_evidence=True,
                )

        # 3. Question regarding Image, Screenshot, or OCR
        if any(w in q_lower for w in ["screenshot", "image", "ocr", "visual", "picture"]):
            img_art = [a for a in all_art if a.artifact_type == "image"]
            if img_art:
                ocr_texts = [a.ocr_text for a in img_art if a.ocr_text]
                if ocr_texts:
                    ans = f"Screenshot analysis extracted visible text via OCR:\n\"{ocr_texts[0][:400]}\""
                else:
                    ans = "Screenshot was uploaded, but no readable text could be extracted by OCR."
                return GroundedQAOutput(
                    answer=ans,
                    referenced_evidence_ids=[img_art[0].id],
                    confidence=0.85,
                    groundedness_assessment="fully_grounded",
                    missing_information_notice=None,
                    grounded_in_evidence=True,
                )
            else:
                return GroundedQAOutput(
                    answer="The requested information was not part of the evidence gathered during this investigation. No image or screenshot artifact was provided.",
                    referenced_evidence_ids=[],
                    confidence=0.9,
                    groundedness_assessment="unsupported",
                    missing_information_notice="No image artifact was submitted as part of this investigation.",
                    grounded_in_evidence=False,
                )

        # 4. Question regarding Audio, Voice, or Transcript
        if any(w in q_lower for w in ["audio", "voice", "transcript", "speech", "call", "recording"]):
            audio_art = [a for a in all_art if a.artifact_type == "audio"]
            if audio_art:
                transcripts = [a.transcript for a in audio_art if a.transcript]
                if transcripts:
                    ans = f"Audio transcription record:\n\"{transcripts[0][:400]}\""
                else:
                    ans = "Audio artifact was submitted, but transcription was empty or unavailable."
                return GroundedQAOutput(
                    answer=ans,
                    referenced_evidence_ids=[audio_art[0].id],
                    confidence=0.85,
                    groundedness_assessment="fully_grounded",
                    missing_information_notice=None,
                    grounded_in_evidence=True,
                )
            else:
                return GroundedQAOutput(
                    answer="The requested information was not part of the evidence gathered during this investigation. No audio recording or voice note was submitted.",
                    referenced_evidence_ids=[],
                    confidence=0.9,
                    groundedness_assessment="unsupported",
                    missing_information_notice="No audio artifact was submitted as part of this investigation.",
                    grounded_in_evidence=False,
                )

        # 5. Question regarding Claims or Fact-Checking
        if any(w in q_lower for w in ["claim", "fact", "true", "false", "hoax", "news", "announcement"]):
            fact_ev = [ev for ev in all_ev if ev.query_type == "fact_check"]
            if fact_ev or all_claims:
                ref_ids = [ev.id for ev in fact_ev]
                details = [f"Claim verification findings:"]
                for ev in fact_ev:
                    details.append(f"Source: {ev.source_reference} | Verdict: {ev.threat_description}")
                for clm in all_claims:
                    details.append(f"Claim: '{clm.claim_text}' (Status: {clm.verification_status})")
                return GroundedQAOutput(
                    answer="\n".join(details),
                    referenced_evidence_ids=ref_ids,
                    confidence=0.9,
                    groundedness_assessment="fully_grounded",
                    missing_information_notice=None,
                    grounded_in_evidence=True,
                )

        # 6. Question regarding Recommended Actions
        if any(w in q_lower for w in ["do", "action", "recommend", "next", "advice", "protect"]):
            recs = ctx["recommendations"]
            if recs:
                ans = "Recommended safety actions based on investigation findings:\n" + "\n".join(f"- {r}" for r in recs)
            else:
                ans = "Standard precaution: Exercise caution and avoid sharing credentials or funds."
            return GroundedQAOutput(
                answer=ans,
                referenced_evidence_ids=[ev.id for ev in all_ev if ev.is_malicious],
                confidence=0.95,
                groundedness_assessment="fully_grounded",
                missing_information_notice=None,
                grounded_in_evidence=True,
            )

        # 7. Uninvestigated, Absent, or Trivia Inquiries
        return GroundedQAOutput(
            answer="The requested information was not part of the evidence gathered during this investigation. No evidence is available in the record to answer this inquiry.",
            referenced_evidence_ids=[],
            confidence=0.0,
            groundedness_assessment="unsupported",
            missing_information_notice="That aspect was not part of the executed investigation checks or stored evidence records.",
            grounded_in_evidence=False,
        )
