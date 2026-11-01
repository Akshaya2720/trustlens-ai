"""TrustLens AI - Investigations Router

Handles text, URL, image, audio, and multimodal investigation endpoints,
status monitoring, evidence inspection, and evidence-grounded Q&A.
"""

import uuid
from typing import Optional
from fastapi import APIRouter, BackgroundTasks, Depends, File, Form, HTTPException, UploadFile, status
from app.api.deps import get_repository
from app.clients.meta_client import meta_client
from app.core.config import settings
from app.core.logging import logger
from app.core.security import compute_sha256, redact_pii, validate_audio_bytes, validate_image_bytes, verify_api_key
from app.db.models import Investigation
from app.db.repository import InvestigationRepository
from app.orchestration.graph import execute_investigation_workflow
from app.orchestration.state import InvestigationState
from app.schemas.evidence import EvidenceItem, ProviderStatusItem, RiskAssessmentSchema
from app.schemas.investigation import (
    ArtifactSummary,
    ClaimInvestigationRequest,
    ExtractedEntitySummary,
    InvestigationEvidenceResponse,
    InvestigationReportResponse,
    InvestigationStatusResponse,
    QuestionRequest,
    QuestionResponse,
    TextInvestigationRequest,
    URLInvestigationRequest,
)
from app.services.evidence_qa import EvidenceQAService
from app.services.safe_url import SafeURLInspector

router = APIRouter(prefix="/investigations", tags=["Investigations"])


def map_investigation_to_response(inv: Investigation) -> InvestigationReportResponse:
    """Helper converting an SQLAlchemy Investigation model to the structured Pydantic report."""
    artifacts = [
        ArtifactSummary(
            id=a.id,
            artifact_type=a.artifact_type,
            filename=a.filename,
            mime_type=a.mime_type,
            file_size=a.file_size,
            sha256_hash=a.sha256_hash,
            ocr_preview=a.ocr_text[:200] if a.ocr_text else None,
            transcript_preview=a.transcript[:200] if a.transcript else None,
        )
        for a in inv.artifacts
    ]

    entities = [
        ExtractedEntitySummary(entity_type=e.entity_type, value=e.value, context=e.context)
        for e in inv.entities
    ]

    claims = [c.claim_text for c in inv.claims]

    provider_statuses = [
        ProviderStatusItem(
            provider_name=ps.provider_name,
            status=ps.status,
            latency_ms=ps.latency_ms,
            checked_at=ps.checked_at,
        )
        for ps in inv.provider_statuses
    ]

    evidence_items = [
        EvidenceItem(
            id=ev.id,
            provider_name=ev.provider_name,
            query_type=ev.query_type,
            query_target=ev.query_target,
            raw_status=ev.raw_status,
            is_malicious=ev.is_malicious,
            threat_description=ev.threat_description,
            source_reference=ev.source_reference,
            normalized_result=ev.normalized_result_json or {},
            retrieved_at=ev.retrieved_at,
            latency_ms=ev.latency_ms,
            error_message=ev.error_message,
        )
        for ev in inv.external_evidence
    ]

    agent_findings_dict = {
        af.agent_name: af.findings_json for af in inv.agent_findings
    }

    risk_assessment = None
    if inv.risk_assessment:
        risk_assessment = RiskAssessmentSchema(
            risk_level=inv.risk_assessment.risk_level,
            risk_score=inv.risk_assessment.risk_score,
            confidence=inv.risk_assessment.confidence,
            indicators=inv.risk_assessment.indicators or [],
            contradictions=inv.risk_assessment.contradictions or [],
            recommendations=inv.risk_assessment.recommendations or [],
            limitations=inv.risk_assessment.limitations or [],
            generated_at=inv.risk_assessment.generated_at,
        )

    # Collect extracted URLs
    extracted_urls = []
    for e in inv.entities:
        if e.entity_type == "url" and e.value not in extracted_urls:
            extracted_urls.append(e.value)
    for ev in inv.external_evidence:
        if ev.query_type == "url" and ev.query_target not in extracted_urls:
            extracted_urls.append(ev.query_target)

    # Collect OCR text from artifacts or findings
    ocr_text = None
    transcription = None
    for a in inv.artifacts:
        if a.ocr_text and not ocr_text:
            ocr_text = a.ocr_text
        if a.transcript and not transcription:
            transcription = a.transcript

    audio_language = None
    audio_duration_seconds = None
    transcription_segments = []
    if "audio_analysis" in agent_findings_dict and isinstance(agent_findings_dict["audio_analysis"], dict):
        audio_findings = agent_findings_dict["audio_analysis"]
        if not transcription:
            transcription = audio_findings.get("full_transcript")
        audio_language = audio_findings.get("language")
        audio_duration_seconds = audio_findings.get("duration_seconds")
        transcription_segments = audio_findings.get("segments", [])

    # Extract discrepancies from agent findings or contradictions
    discrepancies = []
    if "image_analysis" in agent_findings_dict and isinstance(agent_findings_dict["image_analysis"], dict):
        img_findings = agent_findings_dict["image_analysis"]
        discrepancies.extend(img_findings.get("discrepancies", []))
    if inv.risk_assessment and inv.risk_assessment.contradictions:
        for c in inv.risk_assessment.contradictions:
            if "Discrepancy" in c and c not in discrepancies:
                discrepancies.append(c)

    # Verified vs Unverified claims
    verified_claims = []
    unverified_claims = []
    for clm in inv.claims:
        matching_ev = [
            ev for ev in inv.external_evidence
            if ev.query_type == "claim" and ev.query_target == clm.claim_text
        ]
        if matching_ev and matching_ev[0].raw_status in ("ok", "confirmed_match") and not matching_ev[0].error_message:
            threat_desc = matching_ev[0].threat_description or "Verified"
            verified_claims.append(f"{clm.claim_text} ({threat_desc})")
        else:
            unverified_claims.append(clm.claim_text)

    observed_indicators = inv.risk_assessment.indicators if inv.risk_assessment and inv.risk_assessment.indicators else []
    recommended_actions = inv.risk_assessment.recommendations if inv.risk_assessment and inv.risk_assessment.recommendations else []
    limitations = inv.risk_assessment.limitations if inv.risk_assessment and inv.risk_assessment.limitations else []

    active_input_types = []
    if inv.input_type == "multimodal":
        for a in inv.artifacts:
            if a.artifact_type not in active_input_types:
                active_input_types.append(a.artifact_type)
        if any(e.entity_type == "url" for e in inv.entities) and "url" not in active_input_types:
            active_input_types.append("url")
        if not active_input_types:
            active_input_types = ["multimodal"]
    else:
        active_input_types = [inv.input_type] if inv.input_type else ["text"]

    return InvestigationReportResponse(
        investigation_id=inv.id,
        status=inv.status,
        input_type=inv.input_type,
        input_types=active_input_types,
        overall_risk=inv.final_risk_level or "unknown",
        classification_labels=inv.categories or [],
        categories=inv.categories or [],
        final_risk_level=inv.final_risk_level or "unknown",
        final_risk_score=inv.final_risk_score or 0.0,
        confidence=inv.confidence or 0.0,
        summary=inv.summary or "Investigation completed.",
        ruleset_version=inv.ruleset_version,
        model_id=inv.model_id,
        created_at=inv.created_at,
        completed_at=inv.updated_at,
        analysis_timestamp=inv.updated_at or inv.created_at,
        ocr_text=ocr_text,
        transcription=transcription,
        audio_language=audio_language,
        audio_duration_seconds=audio_duration_seconds,
        transcription_segments=transcription_segments,
        extracted_urls=extracted_urls,
        observed_indicators=observed_indicators,
        extraction_discrepancies=discrepancies,
        verified_claims=verified_claims,
        unverified_claims=unverified_claims,
        recommended_actions=recommended_actions,
        limitations=limitations,
        artifacts=artifacts,
        extracted_entities=entities,
        extracted_claims=claims,
        provider_statuses=provider_statuses,
        evidence=evidence_items,
        evidence_sources=evidence_items,
        agent_findings=agent_findings_dict,
        risk_assessment=risk_assessment,
    )


async def persist_investigation_state(
    repo: InvestigationRepository,
    state: InvestigationState,
) -> Investigation:
    """Saves completed workflow state to database models."""
    inv_id = state["investigation_id"]

    # Save entities
    if state.get("extracted_entities"):
        await repo.add_extracted_entities(inv_id, state["extracted_entities"])

    # Save claims
    if state.get("extracted_claims"):
        await repo.add_extracted_claims(inv_id, state["extracted_claims"])

    # Save agent findings
    for agent_name, f_json in state.get("agent_findings", {}).items():
        await repo.add_agent_finding(inv_id, agent_name, f_json)

    # Save external evidence records
    for ev in state.get("external_evidence", []):
        await repo.add_external_evidence(
            investigation_id=inv_id,
            provider_name=ev.get("provider_name", "unknown"),
            query_type=ev.get("query_type", "url"),
            query_target=ev.get("query_target", ""),
            raw_status=str(ev.get("status", "unknown")),
            is_malicious=ev.get("is_malicious"),
            threat_description=ev.get("threat_description"),
            source_reference=ev.get("source_reference"),
            normalized_result_json=ev.get("raw_details"),
            latency_ms=ev.get("latency_ms", 0.0),
            error_message=ev.get("error_message"),
        )

    # Save risk assessment
    ra = state.get("risk_assessment") or {}
    await repo.save_risk_assessment(
        investigation_id=inv_id,
        risk_level=ra.get("risk_level", "unknown"),
        risk_score=ra.get("risk_score", 0.0),
        confidence=ra.get("confidence", 0.0),
        indicators=ra.get("indicators", []),
        contradictions=ra.get("contradictions", []),
        recommendations=ra.get("recommendations", []),
        limitations=ra.get("limitations", []),
        score_breakdown=ra.get("score_breakdown", {}),
    )

    # Update primary investigation record
    await repo.update_investigation_completion(
        investigation_id=inv_id,
        status="completed",
        categories=state.get("categories", []),
        final_risk_level=state.get("final_risk_level", "unknown"),
        final_risk_score=state.get("final_risk_score", 0.0),
        confidence=state.get("confidence", 0.0),
        summary=state.get("summary", ""),
    )

    # Audit log
    await repo.log_audit_event(
        investigation_id=inv_id,
        event_type="investigation_completed",
        actor="system",
        details={"risk_level": state.get("final_risk_level"), "score": state.get("final_risk_score")},
    )

    full_inv = await repo.get_investigation(inv_id)
    return full_inv


@router.post("/text", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_text(
    payload: TextInvestigationRequest,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Step 1 & Workflow: Investigates suspicious text messages or emails."""
    inv_id = str(uuid.uuid4())
    logger.info(f"Received text investigation request [{inv_id}]")

    # Initialize investigation in DB
    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="text",
        raw_input_preview=redact_pii(payload.text),
        model_id=settings.META_MODEL_ID,
    )

    # Store text artifact
    await repo.add_artifact(
        investigation_id=inv_id,
        artifact_type="text",
        file_size=len(payload.text.encode("utf-8")),
        sha256_hash=compute_sha256(payload.text.encode("utf-8")),
    )

    # Initial state
    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "text",
        "raw_text": payload.text,
        "sender_hint": payload.sender_hint,
        "context_notes": payload.context_notes,
        "extracted_entities": [],
        "extracted_claims": [],
        "extracted_urls": [],
        "categories": [],
        "planned_tools": [],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    # Execute LangGraph workflow
    final_state = await execute_investigation_workflow(state)

    # Persist and return report
    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.post("/url", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_url(
    payload: URLInvestigationRequest,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Investigates a suspicious URL or domain against security intelligence."""
    inv_id = str(uuid.uuid4())
    logger.info(f"Received URL investigation request [{inv_id}] for {payload.url}")

    # Validate against SSRF and syntax
    val_res = SafeURLInspector.validate_url(payload.url)
    if not val_res.is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"URL rejected by security inspector: {val_res.reason}",
        )

    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="url",
        raw_input_preview=val_res.normalized_url,
        model_id=settings.META_MODEL_ID,
    )

    await repo.add_artifact(
        investigation_id=inv_id,
        artifact_type="url",
        filename=val_res.hostname,
        sha256_hash=compute_sha256(val_res.normalized_url.encode("utf-8")),
    )

    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "url",
        "raw_text": val_res.normalized_url,
        "context_notes": payload.context_notes,
        "extracted_entities": [{"type": "url", "value": val_res.normalized_url}],
        "extracted_claims": [],
        "extracted_urls": [val_res.normalized_url],
        "categories": ["phishing_and_malicious_links"],
        "planned_tools": ["threat_intel"],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(state)
    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.post("/claim", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_claim(
    payload: ClaimInvestigationRequest,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Phase 6: Investigates public claims, policy statements, viral messages, or misinformation."""
    inv_id = str(uuid.uuid4())
    logger.info(f"Received claim investigation request [{inv_id}]")

    claim_text = payload.claim_text.strip()
    if not claim_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Claim text cannot be empty or whitespace.",
        )

    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="claim",
        raw_input_preview=redact_pii(claim_text[:500]),
        model_id=settings.META_MODEL_ID,
    )

    await repo.add_artifact(
        investigation_id=inv_id,
        artifact_type="text",
        filename="public_claim.txt",
        file_size=len(claim_text.encode("utf-8")),
        sha256_hash=compute_sha256(claim_text.encode("utf-8")),
    )

    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "claim",
        "raw_text": claim_text,
        "context_notes": payload.context_notes,
        "extracted_entities": [],
        "extracted_claims": [{"claim_text": claim_text, "context": payload.context_notes}],
        "extracted_urls": [],
        "categories": ["potential_misinformation"],
        "planned_tools": ["claim_verification"],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(state)
    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.post("/image", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_image(
    file: UploadFile = File(...),
    sender_hint: Optional[str] = Form(None),
    context_notes: Optional[str] = Form(None),
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Investigates a submitted screenshot or image using Meta multimodal vision and OCR."""
    content = await file.read()
    if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes",
        )

    # Secure image validation (magic bytes, decompression limits, dimensions, metadata strip)
    img_fmt, detected_mime, width, height, sanitized_content = validate_image_bytes(
        content,
        allowed_types=settings.ALLOWED_IMAGE_TYPES,
        max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
    )

    inv_id = str(uuid.uuid4())
    img_hash = compute_sha256(sanitized_content)

    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="image",
        raw_input_preview=f"Image upload: {file.filename} ({len(sanitized_content)} bytes, {width}x{height} {img_fmt})",
        model_id=settings.META_MODEL_ID,
    )

    await repo.add_artifact(
        investigation_id=inv_id,
        artifact_type="image",
        filename=file.filename,
        mime_type=detected_mime,
        file_size=len(sanitized_content),
        sha256_hash=img_hash,
    )

    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "image",
        "raw_text": f"Screenshot filename: {file.filename}\nContext: {context_notes or 'None'}",
        "sender_hint": sender_hint,
        "context_notes": context_notes,
        "image_bytes": sanitized_content,
        "filename": file.filename,
        "mime_type": detected_mime,
        "extracted_entities": [],
        "extracted_claims": [],
        "extracted_urls": [],
        "categories": [],
        "planned_tools": [],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(state)

    # Update artifact record with extracted OCR text if available
    if final_state.get("ocr_text"):
        await repo.update_artifact_ocr(inv_id, final_state["ocr_text"])

    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.post("/audio", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_audio(
    file: UploadFile = File(...),
    context_notes: Optional[str] = Form(None),
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Transcribes and investigates audio messages or voice notes using Muse Voice Transcribe and Muse Spark."""
    content = await file.read()

    # Validate audio format, magic bytes, and size
    detected_fmt, detected_mime, file_size, sanitized_content = validate_audio_bytes(
        content,
        allowed_types=settings.ALLOWED_AUDIO_TYPES,
        max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
    )

    inv_id = str(uuid.uuid4())
    audio_hash = compute_sha256(sanitized_content)

    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="audio",
        raw_input_preview=f"Audio message: {file.filename} ({file_size} bytes, {detected_fmt})",
        model_id=settings.META_VOICE_MODEL_ID,
    )

    await repo.add_artifact(
        investigation_id=inv_id,
        artifact_type="audio",
        filename=file.filename,
        mime_type=detected_mime,
        file_size=file_size,
        sha256_hash=audio_hash,
    )

    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "audio",
        "raw_text": f"Audio file: {file.filename}\nContext: {context_notes or 'None'}",
        "context_notes": context_notes,
        "audio_bytes": sanitized_content,
        "filename": file.filename,
        "mime_type": detected_mime,
        "extracted_entities": [],
        "extracted_claims": [],
        "extracted_urls": [],
        "categories": [],
        "planned_tools": [],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(state)

    # Persist transcript back into artifact record if transcribed
    if final_state.get("transcription"):
        await repo.update_artifact_transcript(inv_id, final_state["transcription"])

    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.post("/multimodal", response_model=InvestigationReportResponse, status_code=status.HTTP_201_CREATED)
async def investigate_multimodal(
    text: Optional[str] = Form(None),
    url: Optional[str] = Form(None),
    sender_hint: Optional[str] = Form(None),
    context_notes: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    image_file: Optional[UploadFile] = File(None),
    audio_file: Optional[UploadFile] = File(None),
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Phase 7: Investigates combined submissions containing text, images/screenshots, audio recordings, and URLs."""
    if not any([text, url, file, image_file, audio_file]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one input modality (text, url, image_file, audio_file, or file) must be provided.",
        )

    inv_id = str(uuid.uuid4())
    modalities_desc = []
    if text:
        modalities_desc.append("text")
    if url:
        modalities_desc.append("url")
    if file or image_file:
        modalities_desc.append("image")
    if file or audio_file:
        modalities_desc.append("audio")

    combined_preview = f"Multimodal submission: {', '.join(set(modalities_desc))}"

    await repo.create_investigation(
        investigation_id=inv_id,
        input_type="multimodal",
        raw_input_preview=combined_preview,
        model_id=settings.META_MODEL_ID,
    )

    extracted_urls = []
    if url:
        val_url = SafeURLInspector.validate_url(url)
        if val_url.is_safe:
            extracted_urls.append(val_url.normalized_url)

    image_bytes = None
    audio_bytes = None
    filename = None
    mime_type = None

    # Handle image file
    target_image = image_file
    if not target_image and file:
        f_name = file.filename or ""
        f_type = file.content_type or ""
        if f_type in settings.ALLOWED_IMAGE_TYPES or any(f_name.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp"]):
            target_image = file

    if target_image:
        content = await target_image.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Image file exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes",
            )
        _, detected_mime, _, _, sanitized_img = validate_image_bytes(
            content,
            allowed_types=settings.ALLOWED_IMAGE_TYPES,
            max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
        )
        image_bytes = sanitized_img
        filename = target_image.filename
        mime_type = detected_mime
        sha = compute_sha256(sanitized_img)
        await repo.add_artifact(inv_id, "image", filename, detected_mime, len(sanitized_img), sha)

    # Handle audio file
    target_audio = audio_file
    if not target_audio and file and target_image != file:
        f_name = file.filename or ""
        f_type = file.content_type or ""
        if f_type in settings.ALLOWED_AUDIO_TYPES or any(f_name.lower().endswith(ext) for ext in [".wav", ".mp3", ".m4a", ".ogg", ".webm", ".aac"]):
            target_audio = file

    if target_audio:
        content = await target_audio.read()
        if len(content) > settings.MAX_UPLOAD_SIZE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Audio file exceeds maximum upload size of {settings.MAX_UPLOAD_SIZE_BYTES} bytes",
            )
        _, detected_audio_mime, file_sz, sanitized_audio = validate_audio_bytes(
            content,
            allowed_types=settings.ALLOWED_AUDIO_TYPES,
            max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
        )
        audio_bytes = sanitized_audio
        audio_sha = compute_sha256(sanitized_audio)
        await repo.add_artifact(inv_id, "audio", target_audio.filename, detected_audio_mime, file_sz, audio_sha)

    # Store text artifact if text provided
    if text:
        text_sha = compute_sha256(text.encode("utf-8"))
        await repo.add_artifact(inv_id, "text", "message.txt", "text/plain", len(text.encode("utf-8")), text_sha)

    raw_text_combined = f"{text or ''}\n{url or ''}".strip()

    state: InvestigationState = {
        "investigation_id": inv_id,
        "input_type": "multimodal",
        "raw_text": raw_text_combined,
        "sender_hint": sender_hint,
        "context_notes": context_notes,
        "image_bytes": image_bytes,
        "audio_bytes": audio_bytes,
        "filename": filename,
        "mime_type": mime_type,
        "extracted_entities": [{"type": "url", "value": u} for u in extracted_urls],
        "extracted_claims": [],
        "extracted_urls": extracted_urls,
        "categories": [],
        "planned_tools": [],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(state)

    if final_state.get("transcription"):
        await repo.update_artifact_transcript(inv_id, final_state["transcription"])
    if final_state.get("ocr_text"):
        await repo.update_artifact_ocr(inv_id, final_state["ocr_text"])

    saved_inv = await persist_investigation_state(repo, final_state)
    return map_investigation_to_response(saved_inv)


@router.get("/{investigation_id}", response_model=InvestigationReportResponse)
async def get_investigation_report(
    investigation_id: str,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Retrieves an existing investigation report by ID."""
    inv = await repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )
    return map_investigation_to_response(inv)


@router.get("/{investigation_id}/status", response_model=InvestigationStatusResponse)
async def get_investigation_status(
    investigation_id: str,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Retrieves execution status and progress for an investigation."""
    inv = await repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )
    return InvestigationStatusResponse(
        investigation_id=inv.id,
        status=inv.status,
        input_type=inv.input_type,
        progress=100 if inv.status == "completed" else 50,
        created_at=inv.created_at,
        updated_at=inv.updated_at,
    )


@router.get("/{investigation_id}/evidence", response_model=InvestigationEvidenceResponse)
async def get_investigation_evidence(
    investigation_id: str,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Returns all external provider evidence records and statuses for an investigation."""
    inv = await repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )

    provider_statuses = [
        ProviderStatusItem(
            provider_name=ps.provider_name,
            status=ps.status,
            latency_ms=ps.latency_ms,
            checked_at=ps.checked_at,
        )
        for ps in inv.provider_statuses
    ]

    evidence_items = [
        EvidenceItem(
            id=ev.id,
            provider_name=ev.provider_name,
            query_type=ev.query_type,
            query_target=ev.query_target,
            raw_status=ev.raw_status,
            is_malicious=ev.is_malicious,
            threat_description=ev.threat_description,
            source_reference=ev.source_reference,
            normalized_result=ev.normalized_result_json or {},
            retrieved_at=ev.retrieved_at,
            latency_ms=ev.latency_ms,
            error_message=ev.error_message,
        )
        for ev in inv.external_evidence
    ]

    return InvestigationEvidenceResponse(
        investigation_id=inv.id,
        total_records=len(evidence_items),
        providers_checked=provider_statuses,
        evidence=evidence_items,
    )


@router.post("/{investigation_id}/questions", response_model=QuestionResponse)
async def answer_investigation_question(
    investigation_id: str,
    payload: QuestionRequest,
    repo: InvestigationRepository = Depends(get_repository),
    _user: str = Depends(verify_api_key),
):
    """Answers a user inquiry strictly using the existing evidence and audit records of the investigation.

    Phase 9: Strict grounding, explicit evidence citations, confidence calibration, and absence disclaimers.
    """
    inv = await repo.get_investigation(investigation_id)
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation with ID '{investigation_id}' not found.",
        )

    qa_output = await EvidenceQAService.answer_question(
        inv=inv,
        question=payload.question,
        meta_client=meta_client,
    )

    return QuestionResponse(
        investigation_id=inv.id,
        question=payload.question,
        answer=qa_output.answer,
        grounded_in_evidence=qa_output.grounded_in_evidence,
        referenced_evidence_ids=qa_output.referenced_evidence_ids,
        confidence=qa_output.confidence,
        groundedness_assessment=qa_output.groundedness_assessment,
        missing_information_notice=qa_output.missing_information_notice,
    )
