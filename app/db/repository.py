"""TrustLens AI - Database Repository

Encapsulates CRUD operations, persistence logic, and queries for investigations and evidence.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.db.models import (
    AgentFinding,
    Artifact,
    AuditEvent,
    ExternalEvidence,
    ExtractedClaim,
    ExtractedEntity,
    Investigation,
    InvestigationJob,
    ProviderStatusRecord,
    RiskAssessment,
)


class InvestigationRepository:
    """Data access repository for investigations."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_investigation(
        self,
        investigation_id: str,
        input_type: str,
        raw_input_preview: Optional[str] = None,
        retention_days: int = 30,
        model_id: Optional[str] = None,
    ) -> Investigation:
        now = datetime.now(timezone.utc)
        retention_until = now + timedelta(days=retention_days)
        inv = Investigation(
            id=investigation_id,
            input_type=input_type,
            raw_input_preview=raw_input_preview[:1000] if raw_input_preview else None,
            status="pending",
            model_id=model_id,
            created_at=now,
            retention_until=retention_until,
        )
        self.db.add(inv)
        await self.db.flush()
        return inv

    async def get_investigation(self, investigation_id: str) -> Optional[Investigation]:
        stmt = (
            select(Investigation)
            .where(Investigation.id == investigation_id)
            .options(
                selectinload(Investigation.artifacts),
                selectinload(Investigation.entities),
                selectinload(Investigation.claims),
                selectinload(Investigation.agent_findings),
                selectinload(Investigation.external_evidence),
                selectinload(Investigation.provider_statuses),
                selectinload(Investigation.risk_assessment),
                selectinload(Investigation.jobs),
            )
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def add_artifact(
        self,
        investigation_id: str,
        artifact_type: str,
        filename: Optional[str] = None,
        mime_type: Optional[str] = None,
        file_size: Optional[int] = None,
        sha256_hash: Optional[str] = None,
        storage_path: Optional[str] = None,
        ocr_text: Optional[str] = None,
        transcript: Optional[str] = None,
    ) -> Artifact:
        art = Artifact(
            investigation_id=investigation_id,
            artifact_type=artifact_type,
            filename=filename,
            mime_type=mime_type,
            file_size=file_size,
            sha256_hash=sha256_hash,
            storage_path=storage_path,
            ocr_text=ocr_text,
            transcript=transcript,
        )
        self.db.add(art)
        await self.db.flush()
        return art

    async def update_artifact_ocr(
        self,
        investigation_id: str,
        ocr_text: str,
    ) -> None:
        stmt = (
            select(Artifact)
            .where(Artifact.investigation_id == investigation_id, Artifact.artifact_type == "image")
        )
        res = await self.db.execute(stmt)
        art = res.scalar_one_or_none()
        if art:
            art.ocr_text = ocr_text
            await self.db.flush()

    async def update_artifact_transcript(
        self,
        investigation_id: str,
        transcript: str,
    ) -> None:
        stmt = (
            select(Artifact)
            .where(Artifact.investigation_id == investigation_id, Artifact.artifact_type == "audio")
        )
        res = await self.db.execute(stmt)
        art = res.scalar_one_or_none()
        if art:
            art.transcript = transcript
            await self.db.flush()


    async def add_extracted_entities(
        self,
        investigation_id: str,
        entities: List[Dict[str, Any]],
    ) -> List[ExtractedEntity]:
        records = []
        for e in entities:
            rec = ExtractedEntity(
                investigation_id=investigation_id,
                entity_type=e.get("type", "unknown"),
                value=str(e.get("value", ""))[:512],
                context=e.get("context"),
            )
            self.db.add(rec)
            records.append(rec)
        await self.db.flush()
        return records

    async def add_extracted_claims(
        self,
        investigation_id: str,
        claims: List[Dict[str, Any]],
    ) -> List[ExtractedClaim]:
        records = []
        for c in claims:
            rec = ExtractedClaim(
                investigation_id=investigation_id,
                claim_text=c.get("claim_text", ""),
                context=c.get("context"),
            )
            self.db.add(rec)
            records.append(rec)
        await self.db.flush()
        return records

    async def add_agent_finding(
        self,
        investigation_id: str,
        agent_name: str,
        findings_json: Dict[str, Any],
        latency_ms: float = 0.0,
        status: str = "completed",
    ) -> AgentFinding:
        finding = AgentFinding(
            investigation_id=investigation_id,
            agent_name=agent_name,
            status=status,
            findings_json=findings_json,
            latency_ms=latency_ms,
        )
        self.db.add(finding)
        await self.db.flush()
        return finding

    async def add_external_evidence(
        self,
        investigation_id: str,
        provider_name: str,
        query_type: str,
        query_target: str,
        raw_status: str,
        is_malicious: Optional[bool] = None,
        threat_description: Optional[str] = None,
        source_reference: Optional[str] = None,
        normalized_result_json: Optional[Dict[str, Any]] = None,
        latency_ms: float = 0.0,
        error_message: Optional[str] = None,
    ) -> ExternalEvidence:
        ev = ExternalEvidence(
            investigation_id=investigation_id,
            provider_name=provider_name,
            query_type=query_type,
            query_target=query_target[:1024],
            raw_status=raw_status,
            is_malicious=is_malicious,
            threat_description=threat_description,
            source_reference=source_reference[:1024] if source_reference else None,
            normalized_result_json=normalized_result_json or {},
            latency_ms=latency_ms,
            error_message=error_message,
        )
        self.db.add(ev)
        await self.db.flush()
        return ev

    async def save_risk_assessment(
        self,
        investigation_id: str,
        risk_level: str,
        risk_score: float,
        confidence: float,
        indicators: List[str],
        contradictions: List[str],
        recommendations: List[str],
        limitations: List[str],
    ) -> RiskAssessment:
        ra = RiskAssessment(
            investigation_id=investigation_id,
            risk_level=risk_level,
            risk_score=risk_score,
            confidence=confidence,
            indicators=indicators,
            contradictions=contradictions,
            recommendations=recommendations,
            limitations=limitations,
        )
        self.db.add(ra)
        await self.db.flush()
        return ra

    async def update_investigation_completion(
        self,
        investigation_id: str,
        status: str,
        categories: List[str],
        final_risk_level: str,
        final_risk_score: float,
        confidence: float,
        summary: str,
    ) -> None:
        stmt = select(Investigation).where(Investigation.id == investigation_id)
        res = await self.db.execute(stmt)
        inv = res.scalar_one_or_none()
        if inv:
            inv.status = status
            inv.categories = categories
            inv.final_risk_level = final_risk_level
            inv.final_risk_score = final_risk_score
            inv.confidence = confidence
            inv.summary = summary
            inv.updated_at = datetime.now(timezone.utc)
            await self.db.flush()

    async def create_job(self, job_id: str, investigation_id: str, job_type: str = "standard_investigation") -> InvestigationJob:
        job = InvestigationJob(
            id=job_id,
            investigation_id=investigation_id,
            job_type=job_type,
            status="pending",
            progress=0,
        )
        self.db.add(job)
        await self.db.flush()
        return job

    async def update_job(self, job_id: str, status: str, progress: int = 100, error: Optional[str] = None) -> None:
        stmt = select(InvestigationJob).where(InvestigationJob.id == job_id)
        res = await self.db.execute(stmt)
        job = res.scalar_one_or_none()
        if job:
            job.status = status
            job.progress = progress
            job.error = error
            if status in ("completed", "failed"):
                job.finished_at = datetime.now(timezone.utc)
            await self.db.flush()

    async def log_audit_event(self, investigation_id: str, event_type: str, actor: str = "system", details: Optional[Dict[str, Any]] = None) -> AuditEvent:
        evt = AuditEvent(
            investigation_id=investigation_id,
            event_type=event_type,
            actor=actor,
            details_json=details or {},
        )
        self.db.add(evt)
        await self.db.flush()
        return evt

    async def delete_investigation(self, investigation_id: str) -> bool:
        stmt = delete(Investigation).where(Investigation.id == investigation_id)
        res = await self.db.execute(stmt)
        await self.db.flush()
        return res.rowcount > 0
