"""TrustLens AI - LangGraph Orchestration State Machine Tests"""

import pytest
from app.orchestration.graph import execute_investigation_workflow
from app.orchestration.state import InvestigationState


@pytest.mark.asyncio
async def test_langgraph_workflow_text_execution():
    initial_state: InvestigationState = {
        "investigation_id": "test-orch-001",
        "input_type": "text",
        "raw_text": "Bank alert: please click https://bofa-verify.xyz to update your PIN password.",
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

    final_state = await execute_investigation_workflow(initial_state)

    assert final_state["status"] == "completed"
    assert any("bofa-verify.xyz" in u for u in final_state["extracted_urls"])
    assert len(final_state["planned_tools"]) >= 1
    assert "content_intelligence" in final_state["agent_findings"]
    assert "risk_assessment" in final_state
    assert final_state["final_risk_score"] > 0.0
    assert final_state["final_risk_level"] in ("medium", "high", "critical")
    assert len(final_state["summary"]) > 0


@pytest.mark.asyncio
async def test_langgraph_workflow_url_input():
    initial_state: InvestigationState = {
        "investigation_id": "test-orch-002",
        "input_type": "url",
        "raw_text": "https://www.wikipedia.org",
        "extracted_entities": [],
        "extracted_claims": [],
        "extracted_urls": ["https://www.wikipedia.org"],
        "categories": ["phishing_and_malicious_links"],
        "planned_tools": ["threat_intel"],
        "agent_findings": {},
        "external_evidence": [],
        "provider_statuses": {},
        "status": "pending",
    }

    final_state = await execute_investigation_workflow(initial_state)

    assert final_state["status"] == "completed"
    assert "threat_intel" in final_state["agent_findings"]
    assert final_state["final_risk_level"] == "low"
