"""TrustLens AI - LangGraph Investigation Orchestrator

Explicit, deterministic state machine coordinating content normalization,
agent classification, concurrent specialist checks, and risk synthesis.
"""

import asyncio
from typing import Any, Dict, List
from langgraph.graph import END, START, StateGraph
from app.agents.claim_verification import ClaimVerificationAgent
from app.agents.content_intelligence import ContentIntelligenceAgent
from app.agents.impersonation_analysis import ImpersonationAnalysisAgent
from app.agents.risk_synthesis import RiskSynthesisAgent
from app.agents.scam_detection import ScamDetectionAgent
from app.agents.threat_intelligence import ThreatIntelligenceAgent
from app.clients.threat_intel.base import NormalizedEvidenceRecord, ProviderStatus
from app.core.logging import logger
from app.orchestration.state import InvestigationState
from app.schemas.agent_outputs import (
    ClaimVerificationOutput,
    ContentIntelligenceOutput,
    ImpersonationAnalysisOutput,
    ScamDetectionOutput,
    ThreatIntelligenceOutput,
)
from app.services.content_normalizer import ContentNormalizer
from app.services.multimodal.audio_processor import AudioProcessor
from app.services.multimodal.image_processor import ImageProcessor
from app.services.safe_url import SafeURLInspector


async def normalize_content_node(state: InvestigationState) -> Dict[str, Any]:
    """Step 2: Normalizes content, processes images/audio if provided, and extracts entities."""
    logger.info(f"[{state['investigation_id']}] Running Normalize Content Node (Input: {state.get('input_type')})")
    text = state.get("raw_text") or ""
    extracted_entities = state.get("extracted_entities") or []
    extracted_urls = state.get("extracted_urls") or []

    # Handle image input
    if state.get("image_bytes"):
        try:
            img_res = await ImageProcessor.process_image(
                image_bytes=state["image_bytes"],
                filename=state.get("filename", "upload.png"),
                mime_type=state.get("mime_type", "image/png"),
            )
            text += f"\n[Extracted Visual & OCR Content]:\n{img_res.extracted_text}"
        except Exception as e:
            logger.warning(f"Image processing error: {e}")

    # Handle audio input
    if state.get("audio_bytes"):
        try:
            audio_res = await AudioProcessor.process_audio(
                audio_bytes=state["audio_bytes"],
                filename=state.get("filename", "voice_note.mp3"),
                mime_type=state.get("mime_type", "audio/mpeg"),
            )
            if audio_res.full_transcript:
                text += f"\n[Transcribed Audio Content]:\n{audio_res.full_transcript}"
        except Exception as e:
            logger.warning(f"Audio processing error: {e}")

    # Deterministic regex entity harvesting
    norm_entities = ContentNormalizer.extract_entities(text)
    for ent in norm_entities:
        if ent["value"] not in [e.get("value") for e in extracted_entities]:
            extracted_entities.append(ent)
        if ent["type"] == "url" and ent["value"] not in extracted_urls:
            extracted_urls.append(ent["value"])

    # If the input itself is a raw URL
    if state.get("input_type") == "url" and state.get("raw_text"):
        norm_input_url = SafeURLInspector.normalize_url(state["raw_text"].strip())
        if norm_input_url not in extracted_urls:
            extracted_urls.append(norm_input_url)

    return {
        "raw_text": text.strip(),
        "extracted_entities": extracted_entities,
        "extracted_urls": extracted_urls,
    }


async def classify_investigation_node(state: InvestigationState) -> Dict[str, Any]:
    """Step 3: Agent A (Content Intelligence) classifies the investigation categories and claims."""
    logger.info(f"[{state['investigation_id']}] Running Agent A: Content Intelligence")
    text = state.get("raw_text", "")
    sender_hint = state.get("sender_hint")
    context_notes = state.get("context_notes")
    entities = state.get("extracted_entities", [])

    intel_output = await ContentIntelligenceAgent.analyze(
        text=text,
        sender_hint=sender_hint,
        context_notes=context_notes,
        pre_extracted_entities=entities,
    )

    claims_list = [{"claim_text": c.claim_text, "context": c.context} for c in intel_output.claims]
    for ent in intel_output.entities:
        if ent.value not in [e.get("value") for e in entities]:
            entities.append({"type": ent.type, "value": ent.value, "context": ent.context})
        if ent.type == "url" and ent.value not in state.get("extracted_urls", []):
            state.get("extracted_urls", []).append(ent.value)

    return {
        "categories": intel_output.categories,
        "extracted_claims": claims_list,
        "extracted_entities": entities,
        "planned_tools": intel_output.recommended_tools,
        "agent_findings": {"content_intelligence": intel_output.model_dump()},
    }


async def plan_specialist_checks_node(state: InvestigationState) -> Dict[str, Any]:
    """Step 4: Deterministically ensures all relevant tools are scheduled based on extracted features."""
    logger.info(f"[{state['investigation_id']}] Running Plan Specialist Checks Node")
    planned = list(state.get("planned_tools", []))
    urls = state.get("extracted_urls", [])
    text = state.get("raw_text", "").lower()

    if urls and "threat_intel" not in planned:
        planned.append("threat_intel")

    if any(w in text for w in ["bank", "support", "security", "paypal", "apple", "irs", "amazon"]) or state.get("sender_hint"):
        if "impersonation_check" not in planned:
            planned.append("impersonation_check")

    if any(w in text for w in ["urgent", "immediately", "otp", "password", "suspended", "wire", "gift card", "crypto", "pay"]):
        if "scam_analysis" not in planned:
            planned.append("scam_analysis")

    if state.get("extracted_claims") and "claim_verification" not in planned:
        planned.append("claim_verification")

    # If no checks were planned, run scam_analysis as default baseline
    if not planned:
        planned.append("scam_analysis")

    return {"planned_tools": planned}


async def execute_specialist_checks_node(state: InvestigationState) -> Dict[str, Any]:
    """Step 5 & 6: Concurrently executes independent specialist agents and gathers external evidence."""
    logger.info(f"[{state['investigation_id']}] Running Specialist Checks: {state.get('planned_tools')}")
    planned = set(state.get("planned_tools", []))
    text = state.get("raw_text", "")
    sender_hint = state.get("sender_hint")
    urls = state.get("extracted_urls", [])
    claims = [c.get("claim_text", "") for c in state.get("extracted_claims", [])]

    findings = dict(state.get("agent_findings", {}))
    external_evidence = list(state.get("external_evidence", []))
    provider_statuses = dict(state.get("provider_statuses", {}))

    # Construct tasks
    tasks = []
    task_keys = []

    if "threat_intel" in planned and urls:
        threat_agent = ThreatIntelligenceAgent()
        tasks.append(threat_agent.analyze(urls))
        task_keys.append("threat_intel")

    if "scam_analysis" in planned or not planned:
        tasks.append(ScamDetectionAgent.analyze(text))
        task_keys.append("scam_analysis")

    if "impersonation_check" in planned:
        tasks.append(ImpersonationAnalysisAgent.analyze(text, sender_hint=sender_hint, extracted_urls=urls))
        task_keys.append("impersonation_check")

    if "claim_verification" in planned and claims:
        claim_agent = ClaimVerificationAgent()
        tasks.append(claim_agent.analyze(claims))
        task_keys.append("claim_verification")

    # Run concurrently
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for key, res in zip(task_keys, results):
        if isinstance(res, Exception):
            logger.error(f"Specialist agent '{key}' execution failed: {res}")
            findings[key] = {"error": str(res)}
            continue

        if key == "threat_intel":
            output, records = res
            findings[key] = output.model_dump(mode="json")
            for r in records:
                external_evidence.append(r.model_dump(mode="json"))
                provider_statuses[r.provider_name] = r.status.value

        elif key == "claim_verification":
            output, records = res
            findings[key] = output.model_dump(mode="json")
            for r in records:
                external_evidence.append(r.model_dump(mode="json"))
                provider_statuses[r.provider_name] = r.status.value

        elif key == "scam_analysis":
            findings[key] = res.model_dump(mode="json")

        elif key == "impersonation_check":
            findings[key] = res.model_dump(mode="json")

    return {
        "agent_findings": findings,
        "external_evidence": external_evidence,
        "provider_statuses": provider_statuses,
    }


async def synthesize_findings_node(state: InvestigationState) -> Dict[str, Any]:
    """Step 7: Reconciles all findings, runs deterministic risk engine, and produces final summary."""
    logger.info(f"[{state['investigation_id']}] Running Agent F: Risk Synthesis & Deterministic Risk Engine")
    findings = state.get("agent_findings", {})
    ev_records_raw = state.get("external_evidence", [])
    provider_statuses = state.get("provider_statuses", {})

    # Reconstruct normalized evidence records
    ev_records: List[NormalizedEvidenceRecord] = []
    for r in ev_records_raw:
        try:
            ev_records.append(NormalizedEvidenceRecord(**r))
        except Exception:
            pass

    content_intel = ContentIntelligenceOutput(**findings.get("content_intelligence", {}))
    threat_intel = ThreatIntelligenceOutput(**findings["threat_intel"]) if "threat_intel" in findings and "checked_urls" in findings["threat_intel"] else None
    scam_detection = ScamDetectionOutput(**findings["scam_analysis"]) if "scam_analysis" in findings and "urgency_detected" in findings["scam_analysis"] else None
    impersonation = ImpersonationAnalysisOutput(**findings["impersonation_check"]) if "impersonation_check" in findings and "is_domain_mismatch" in findings["impersonation_check"] else None
    claim_verification = ClaimVerificationOutput(**findings["claim_verification"]) if "claim_verification" in findings and "claims_analyzed" in findings["claim_verification"] else None

    synth_output, assessment = await RiskSynthesisAgent.synthesize(
        content_intel=content_intel,
        threat_intel=threat_intel,
        scam_detection=scam_detection,
        impersonation=impersonation,
        claim_verification=claim_verification,
        evidence_records=ev_records,
        provider_statuses=provider_statuses,
    )

    findings["risk_synthesis"] = synth_output.model_dump(mode="json")

    return {
        "agent_findings": findings,
        "risk_assessment": assessment.model_dump(mode="json"),
        "final_risk_level": assessment.risk_level,
        "final_risk_score": assessment.risk_score,
        "confidence": assessment.confidence,
        "summary": synth_output.model_explanation,
        "status": "completed",
    }


def build_investigation_graph():
    """Builds and compiles the LangGraph State Machine for TrustLens AI."""
    workflow = StateGraph(InvestigationState)

    # Add Nodes
    workflow.add_node("normalize_content", normalize_content_node)
    workflow.add_node("classify_investigation", classify_investigation_node)
    workflow.add_node("plan_specialist_checks", plan_specialist_checks_node)
    workflow.add_node("execute_specialist_checks", execute_specialist_checks_node)
    workflow.add_node("synthesize_findings", synthesize_findings_node)

    # Add Directed Edges
    workflow.add_edge(START, "normalize_content")
    workflow.add_edge("normalize_content", "classify_investigation")
    workflow.add_edge("classify_investigation", "plan_specialist_checks")
    workflow.add_edge("plan_specialist_checks", "execute_specialist_checks")
    workflow.add_edge("execute_specialist_checks", "synthesize_findings")
    workflow.add_edge("synthesize_findings", END)

    return workflow.compile()


investigation_graph = build_investigation_graph()


async def execute_investigation_workflow(state: InvestigationState) -> InvestigationState:
    """Executes the complete compiled LangGraph workflow from an initial state."""
    result = await investigation_graph.ainvoke(state)
    return result
