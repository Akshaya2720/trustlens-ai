"""TrustLens AI - Phase 1 Controlled Investigation Pipeline

Implements the single, modular, 10-stage investigation workflow:
1. Receive & validate input
2. Analyze text using Meta AI & extract observable patterns
3. Extract and normalize URLs safely
4. Query configured threat-intelligence provider (VirusTotal, fallback URLhaus)
5. Collect findings & source evidence records
6. Apply deterministic risk rules (DeterministicRiskEngine)
7. Generate evidence-grounded explanation
8. Validate final result
9. Persist investigation to PostgreSQL / SQLite database
10. Return investigation ID and report
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from app.clients.meta_client import MetaModelClient, meta_client
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.clients.threat_intel.urlhaus import URLhausClient
from app.clients.threat_intel.virustotal import VirusTotalClient
from app.core.logging import logger
from app.db.models import Investigation
from app.db.repository import InvestigationRepository
from app.db.session import AsyncSessionLocal
from app.schemas.agent_outputs import (
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.schemas.evidence import EvidenceItem, ProviderStatusItem, RiskAssessmentSchema
from app.schemas.investigation import (
    ArtifactSummary,
    ExtractedEntitySummary,
    InvestigationReportResponse,
)
from app.services.risk_engine import DeterministicRiskEngine
from app.services.safe_url import SafeURLInspector
from app.services.text_analysis import ObservationType, TextAnalysisResult, TextAnalysisService


class InvestigationPipeline:
    """Stage-by-stage controlled investigation orchestrator."""

    def __init__(
        self,
        meta_cli: Optional[MetaModelClient] = None,
        vt_client: Optional[VirusTotalClient] = None,
        urlhaus_client: Optional[URLhausClient] = None,
    ):
        self.meta_client = meta_cli or meta_client
        self.vt_client = vt_client or VirusTotalClient()
        self.urlhaus_client = urlhaus_client or URLhausClient()

    async def execute_text_investigation(
        self,
        text: str,
        investigation_id: Optional[str] = None,
        sender_hint: Optional[str] = None,
        context_notes: Optional[str] = None,
        session: Optional[AsyncSession] = None,
    ) -> InvestigationReportResponse:
        """Runs the 10-stage controlled investigation pipeline."""
        inv_id = investigation_id or str(uuid.uuid4())
        logger.info(f"[{inv_id}] Starting Phase 1 text investigation pipeline")

        # Stage 1: Receive and validate input
        clean_text = text.strip()
        if not clean_text:
            raise ValueError("Input text cannot be empty or purely whitespace.")

        # Stage 2: Analyze text (direct observations + Meta AI reasoning)
        analysis_result: TextAnalysisResult = await TextAnalysisService.analyze_text(
            text=clean_text,
            sender_hint=sender_hint,
            client=self.meta_client,
        )

        # Stage 3: Extract and normalize URLs
        urls = analysis_result.extracted_urls
        logger.info(f"[{inv_id}] Extracted {len(urls)} URL(s): {urls}")

        # Stage 4: Query Threat Intelligence Providers
        evidence_records: List[NormalizedEvidenceRecord] = []
        provider_statuses: Dict[str, str] = {}

        for url in urls:
            # Query VirusTotal first
            vt_record = await self.vt_client.check_url(url)
            evidence_records.append(vt_record)
            provider_statuses["VirusTotal"] = vt_record.status.value

            # If VirusTotal is unconfigured or returns NO_MATCH, query live URLhaus
            if vt_record.status in (ProviderStatus.NOT_CONFIGURED, ProviderStatus.NO_MATCH, ProviderStatus.UNAVAILABLE):
                urlhaus_record = await self.urlhaus_client.check_url(url)
                evidence_records.append(urlhaus_record)
                provider_statuses["URLhaus"] = urlhaus_record.status.value

        # Stage 5: Collect findings & source records
        agent_findings: Dict[str, Any] = {
            "text_analysis": analysis_result.model_dump(mode="json"),
            "scam_analysis": {
                "urgency_detected": analysis_result.has_urgency,
                "credential_or_otp_harvesting": analysis_result.has_credential_harvesting,
                "financial_demands": analysis_result.has_financial_demands,
                "extortion_threats": analysis_result.has_extortion_threats,
                "observed_phrases": [
                    o.quote for o in analysis_result.direct_observations
                    if o.observation_type in (
                        ObservationType.URGENCY_INDICATOR,
                        ObservationType.CREDENTIAL_REQUEST,
                        ObservationType.EXTORTION_THREAT,
                    )
                ],
                "scam_likelihood": "high" if (analysis_result.has_credential_harvesting or analysis_result.has_urgency) else "low",
                "reasoning": analysis_result.observable_summary,
            },
        }

        if analysis_result.potential_impersonation:
            agent_findings["impersonation_check"] = analysis_result.potential_impersonation.model_dump(mode="json")

        # Construct typed specialist schemas for RiskEngine
        scam_out = ScamDetectionOutput(
            urgency_detected=analysis_result.has_urgency,
            urgency_indicators=[o.quote for o in analysis_result.direct_observations if o.observation_type == ObservationType.URGENCY_INDICATOR],
            credential_or_otp_harvesting=analysis_result.has_credential_harvesting,
            financial_demands=analysis_result.has_financial_demands,
            payment_instructions=[],
            threat_or_reward_patterns=[],
            social_engineering_tactics=["artificial urgency"] if analysis_result.has_urgency else [],
            scam_likelihood="high" if (analysis_result.has_credential_harvesting or analysis_result.has_urgency) else "low",
            observed_phrases=[
                o.quote for o in analysis_result.direct_observations
                if o.observation_type in (
                    ObservationType.URGENCY_INDICATOR,
                    ObservationType.CREDENTIAL_REQUEST,
                    ObservationType.EXTORTION_THREAT,
                )
            ],
            reasoning=analysis_result.observable_summary,
        )

        impersonation_out = None
        if analysis_result.potential_impersonation:
            impersonation_out = ImpersonationAnalysisOutput(
                claimed_organization=analysis_result.potential_impersonation.claimed_organization,
                sender_domain_or_address=analysis_result.potential_impersonation.sender_domain_or_address,
                is_domain_mismatch=analysis_result.potential_impersonation.is_domain_mismatch,
                brand_spoofing_indicators=[],
                inconsistencies=[],
                official_domain_candidate=None,
                reasoning=analysis_result.potential_impersonation.evidence_citation or "Direct entity alignment",
            )

        threat_intel_out = ThreatIntelligenceOutput(
            checked_urls=urls,
            malware_detected=any(bool(r.is_malware) for r in evidence_records),
            phishing_detected=any(bool(r.is_phishing) for r in evidence_records),
            suspicious_redirects_detected=False,
            provider_results=[],
            summary="Threat intelligence checks executed.",
        )

        # Stage 6: Apply deterministic risk rules
        assessment = DeterministicRiskEngine.calculate_risk(
            threat_intel=threat_intel_out,
            scam_detection=scam_out,
            impersonation=impersonation_out,
            claim_verification=None,
            evidence_records=evidence_records,
            provider_statuses=provider_statuses,
        )

        # Stage 7: Generate evidence-grounded explanation
        summary_lines = [
            f"TrustLens automated analysis concluded a {assessment.risk_level.upper()} risk rating (Score: {assessment.risk_score:.1f}/100, Confidence: {int(assessment.confidence * 100)}%).",
        ]
        if assessment.indicators:
            summary_lines.append(f"Key indicators: {'; '.join(assessment.indicators[:3])}.")
        if assessment.recommendations:
            summary_lines.append(f"Recommended action: {assessment.recommendations[0]}")
        explanation = " ".join(summary_lines)

        # Stage 8: Validate the final result
        # Convert evidence records to schema items
        evidence_items: List[EvidenceItem] = []
        for ev in evidence_records:
            evidence_items.append(
                EvidenceItem(
                    id=str(uuid.uuid4()),
                    provider_name=ev.provider_name,
                    query_type=ev.query_type,
                    query_target=ev.query_target,
                    raw_status=ev.status.value,
                    is_malicious=ev.is_malicious,
                    threat_description=ev.threat_description,
                    source_reference=ev.source_reference,
                    normalized_result=ev.raw_details or {},
                    retrieved_at=datetime.now(timezone.utc),
                    latency_ms=ev.latency_ms,
                    error_message=ev.error_message,
                )
            )

        provider_status_items: List[ProviderStatusItem] = [
            ProviderStatusItem(
                provider_name=name,
                status=st,
                checked_at=datetime.now(timezone.utc),
            )
            for name, st in provider_statuses.items()
        ]

        extracted_entities = [
            ExtractedEntitySummary(
                entity_type=o.observation_type.value,
                value=o.extracted_value,
                context=o.context,
            )
            for o in analysis_result.direct_observations
        ]

        report = InvestigationReportResponse(
            investigation_id=inv_id,
            status="completed",
            input_type="text",
            categories=["phishing_and_malicious_links"] if urls else (["social_engineering"] if analysis_result.has_urgency else ["unclear_or_insufficient_evidence"]),
            final_risk_level=assessment.risk_level,
            final_risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            summary=explanation,
            ruleset_version=DeterministicRiskEngine.RULESET_VERSION,
            model_id=self.meta_client.model_id if self.meta_client.is_configured else "deterministic-fallback",
            created_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            artifacts=[],
            extracted_entities=extracted_entities,
            extracted_claims=analysis_result.claims_for_verification,
            provider_statuses=provider_status_items,
            evidence=evidence_items,
            agent_findings=agent_findings,
            risk_assessment=RiskAssessmentSchema(
                risk_level=assessment.risk_level,
                risk_score=assessment.risk_score,
                confidence=assessment.confidence,
                indicators=assessment.indicators,
                contradictions=assessment.contradictions,
                recommendations=assessment.recommendations,
                limitations=assessment.limitations,
                generated_at=assessment.generated_at,
            ),
        )

        # Stage 9: Persist the investigation
        if session is not None:
            await self._persist_report(session, report, clean_text, evidence_records)
        else:
            async with AsyncSessionLocal() as db_session:
                await self._persist_report(db_session, report, clean_text, evidence_records)

        logger.info(f"[{inv_id}] Investigation successfully persisted with score {assessment.risk_score}")

        # Stage 10: Return the investigation ID and report
        return report

    async def _persist_report(
        self,
        session: AsyncSession,
        report: InvestigationReportResponse,
        raw_text: str,
        evidence_records: List[NormalizedEvidenceRecord],
    ) -> None:
        """Persists investigation state to database models."""
        repo = InvestigationRepository(session)
        inv_id = report.investigation_id

        # Create or update primary investigation row
        existing = await repo.get_investigation(inv_id)
        if not existing:
            await repo.create_investigation(
                investigation_id=inv_id,
                input_type="text",
                raw_input_preview=raw_text[:500],
            )

        # Persist extracted entities
        entities_dicts = [
            {"type": e.entity_type, "value": e.value, "context": e.context}
            for e in report.extracted_entities
        ]
        if entities_dicts:
            await repo.add_extracted_entities(inv_id, entities_dicts)

        # Persist claims
        if report.extracted_claims:
            claims_dicts = [{"claim_text": c} for c in report.extracted_claims]
            await repo.add_extracted_claims(inv_id, claims_dicts)

        # Persist findings
        for agent_name, f_json in report.agent_findings.items():
            await repo.add_agent_finding(inv_id, agent_name, f_json)

        # Persist external evidence
        for ev in evidence_records:
            await repo.add_external_evidence(
                investigation_id=inv_id,
                provider_name=ev.provider_name,
                query_type=ev.query_type,
                query_target=ev.query_target,
                raw_status=ev.status.value,
                is_malicious=ev.is_malicious,
                threat_description=ev.threat_description,
                source_reference=ev.source_reference,
                normalized_result_json=ev.raw_details,
                latency_ms=ev.latency_ms,
                error_message=ev.error_message,
            )

        # Persist risk assessment
        if report.risk_assessment:
            ra = report.risk_assessment
            await repo.save_risk_assessment(
                investigation_id=inv_id,
                risk_level=ra.risk_level,
                risk_score=ra.risk_score,
                confidence=ra.confidence,
                indicators=ra.indicators,
                contradictions=ra.contradictions,
                recommendations=ra.recommendations,
                limitations=ra.limitations,
            )

        # Update status to completed
        await repo.update_investigation_completion(
            investigation_id=inv_id,
            status="completed",
            categories=report.categories,
            final_risk_level=report.final_risk_level,
            final_risk_score=report.final_risk_score,
            confidence=report.confidence,
            summary=report.summary,
        )

        await repo.log_audit_event(
            investigation_id=inv_id,
            event_type="phase1_pipeline_completed",
            actor="orchestrator",
            details={"risk_level": report.final_risk_level, "score": report.final_risk_score},
        )


pipeline = InvestigationPipeline()
