"""TrustLens AI - SQLAlchemy Database Models

Defines the relational schema for investigations, artifacts, extracted entities/claims,
specialist agent findings, external evidence records, risk assessments, jobs, and audit events.
"""

from datetime import datetime, timezone
import uuid
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    status = Column(String(32), default="pending", index=True)  # pending, processing, completed, failed
    input_type = Column(String(32), nullable=False)            # text, url, image, audio, multimodal
    raw_input_preview = Column(Text, nullable=True)
    categories = Column(JSON, default=list)                     # list of classification categories
    final_risk_level = Column(String(16), default="unknown")    # low, medium, high, critical, unknown
    final_risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    summary = Column(Text, nullable=True)
    ruleset_version = Column(String(32), default="v1.0.0")
    model_id = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now)
    retention_until = Column(DateTime(timezone=True), nullable=True, index=True)

    # Relationships
    artifacts = relationship("Artifact", back_populates="investigation", cascade="all, delete-orphan")
    entities = relationship("ExtractedEntity", back_populates="investigation", cascade="all, delete-orphan")
    claims = relationship("ExtractedClaim", back_populates="investigation", cascade="all, delete-orphan")
    agent_findings = relationship("AgentFinding", back_populates="investigation", cascade="all, delete-orphan")
    external_evidence = relationship("ExternalEvidence", back_populates="investigation", cascade="all, delete-orphan")
    provider_statuses = relationship("ProviderStatusRecord", back_populates="investigation", cascade="all, delete-orphan")
    risk_assessment = relationship("RiskAssessment", back_populates="investigation", uselist=False, cascade="all, delete-orphan")
    jobs = relationship("InvestigationJob", back_populates="investigation", cascade="all, delete-orphan")
    audit_events = relationship("AuditEvent", back_populates="investigation", cascade="all, delete-orphan")


class Artifact(Base):
    __tablename__ = "artifacts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    artifact_type = Column(String(32), nullable=False)  # text, image, audio, url
    filename = Column(String(255), nullable=True)
    mime_type = Column(String(128), nullable=True)
    file_size = Column(Integer, nullable=True)
    sha256_hash = Column(String(64), nullable=True, index=True)
    storage_path = Column(String(512), nullable=True)
    ocr_text = Column(Text, nullable=True)
    transcript = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="artifacts")


class ExtractedEntity(Base):
    __tablename__ = "extracted_entities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    entity_type = Column(String(32), nullable=False)  # url, email, phone, organization, crypto_address, money
    value = Column(String(512), nullable=False)
    context = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="entities")


class ExtractedClaim(Base):
    __tablename__ = "extracted_claims"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    claim_text = Column(Text, nullable=False)
    context = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="claims")


class AgentFinding(Base):
    __tablename__ = "agent_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    agent_name = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default="completed")
    findings_json = Column(JSON, default=dict)
    latency_ms = Column(Float, default=0.0)
    created_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="agent_findings")


class ExternalEvidence(Base):
    __tablename__ = "external_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(64), nullable=False, index=True)
    query_type = Column(String(32), nullable=False)
    query_target = Column(String(1024), nullable=False)
    raw_status = Column(String(32), nullable=False)
    is_malicious = Column(Boolean, nullable=True)
    threat_description = Column(Text, nullable=True)
    source_reference = Column(String(1024), nullable=True)
    normalized_result_json = Column(JSON, default=dict)
    retrieved_at = Column(DateTime(timezone=True), default=utc_now)
    latency_ms = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)

    investigation = relationship("Investigation", back_populates="external_evidence")


class ProviderStatusRecord(Base):
    __tablename__ = "provider_statuses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    provider_name = Column(String(64), nullable=False)
    status = Column(String(32), nullable=False)
    latency_ms = Column(Float, default=0.0)
    checked_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="provider_statuses")


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)
    risk_level = Column(String(16), nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    indicators = Column(JSON, default=list)
    contradictions = Column(JSON, default=list)
    recommendations = Column(JSON, default=list)
    limitations = Column(JSON, default=list)
    score_breakdown = Column(JSON, default=dict)
    generated_at = Column(DateTime(timezone=True), default=utc_now)

    investigation = relationship("Investigation", back_populates="risk_assessment")


class InvestigationJob(Base):
    __tablename__ = "investigation_jobs"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    job_type = Column(String(32), default="standard_investigation")
    status = Column(String(32), default="pending", index=True)  # pending, in_progress, completed, failed
    progress = Column(Integer, default=0)
    error = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now)
    finished_at = Column(DateTime(timezone=True), nullable=True)

    investigation = relationship("Investigation", back_populates="jobs")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    investigation_id = Column(String(36), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=True, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor = Column(String(64), default="system")
    details_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)

    investigation = relationship("Investigation", back_populates="audit_events")


# Composite indexes for fast query lookups
Index("ix_investigations_status_created", Investigation.status, Investigation.created_at)
Index("ix_evidence_inv_provider", ExternalEvidence.investigation_id, ExternalEvidence.provider_name)
