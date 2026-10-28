"""TrustLens AI - Agent A: Content Intelligence

Analyzes submitted content, categorizes threats, extracts entities and factual claims,
identifies ambiguities, and recommends specialist checks.
"""

from typing import Any, Dict, List, Optional
from app.clients.meta_client import meta_client
from app.core.logging import logger
from app.core.security import isolate_untrusted_input
from app.schemas.agent_outputs import ClaimItem, ContentIntelligenceOutput, EntityItem
from app.services.content_normalizer import ContentNormalizer


class ContentIntelligenceAgent:
    """Agent A: Content Intelligence."""

    SYSTEM_PROMPT = (
        "You are Agent A (Content Intelligence) for TrustLens AI, a digital safety investigation system.\n"
        "Your duty is to objectively inspect the submitted message, extract entities, identify claims, "
        "and determine investigation categories.\n"
        "Categories must be chosen from: ['phishing_and_malicious_links', 'financial_scams', "
        "'social_engineering', 'possible_impersonation', 'suspicious_attachments', "
        "'potential_misinformation', 'unclear_or_insufficient_evidence'].\n"
        "Recommended tools must be from: ['threat_intel', 'scam_analysis', 'impersonation_check', 'claim_verification'].\n"
        "Do NOT invent facts or extrapolate beyond observable content."
    )

    @classmethod
    async def analyze(
        cls,
        text: str,
        sender_hint: Optional[str] = None,
        context_notes: Optional[str] = None,
        pre_extracted_entities: Optional[List[Dict[str, Any]]] = None,
    ) -> ContentIntelligenceOutput:
        # Step 1: Deterministic regex entity harvesting as ground baseline
        regex_entities = pre_extracted_entities or ContentNormalizer.extract_entities(text)
        has_urls = any(e["type"] == "url" for e in regex_entities)
        has_money = any(e["type"] in ("money", "crypto_address") for e in regex_entities)
        observable_urgency = ContentNormalizer.extract_observable_urgency(text)

        # Baseline recommendations based on deterministic features
        recommended_tools = []
        if has_urls:
            recommended_tools.append("threat_intel")
        if has_money or observable_urgency:
            recommended_tools.append("scam_analysis")
        if sender_hint or any(w in text.lower() for w in ["bank", "support", "security", "irs", "paypal", "apple", "google", "amazon"]):
            recommended_tools.append("impersonation_check")

        # Fallback structured output if Meta API is unconfigured
        if not meta_client.is_configured:
            entities_list = [EntityItem(type=e["type"], value=e["value"], context=e.get("context")) for e in regex_entities]
            cats = []
            if has_urls:
                cats.append("phishing_and_malicious_links")
            if has_money:
                cats.append("financial_scams")
            if observable_urgency:
                cats.append("social_engineering")
            if not cats:
                cats.append("unclear_or_insufficient_evidence")

            return ContentIntelligenceOutput(
                language="en",
                categories=cats,
                entities=entities_list,
                claims=[],
                suspicious_phrases=observable_urgency,
                recommended_tools=recommended_tools or ["scam_analysis"],
                missing_information=["Independent online fact-checking unavailable (MODEL_API_KEY unconfigured)."],
            )

        # Step 2: Use Meta Model API (Muse Spark 1.3) for nuanced reasoning
        user_message = (
            f"Please analyze the following submitted content:\n"
            f"{isolate_untrusted_input(text, 'CONTENT')}\n"
        )
        if sender_hint:
            user_message += f"Claimed Sender: {sender_hint}\n"
        if context_notes:
            user_message += f"Context Notes: {context_notes}\n"

        messages = [
            {"role": "system", "content": cls.SYSTEM_PROMPT},
            {"role": "user", "content": user_message},
        ]

        try:
            output, metadata = await meta_client.generate_structured(
                messages=messages,
                schema=ContentIntelligenceOutput,
                temperature=0.1,
            )

            # Ensure all deterministic regex entities are preserved
            existing_vals = {e.value for e in output.entities}
            for re_e in regex_entities:
                if re_e["value"] not in existing_vals:
                    output.entities.append(
                        EntityItem(type=re_e["type"], value=re_e["value"], context=re_e.get("context"))
                    )

            # Ensure recommended tools include deterministic triggers
            for t in recommended_tools:
                if t not in output.recommended_tools:
                    output.recommended_tools.append(t)

            return output

        except Exception as e:
            logger.warning(f"Agent A structured inference error: {e}. Falling back to deterministic baseline.")
            entities_list = [EntityItem(type=e["type"], value=e["value"], context=e.get("context")) for e in regex_entities]
            return ContentIntelligenceOutput(
                language="en",
                categories=["phishing_and_malicious_links"] if has_urls else ["unclear_or_insufficient_evidence"],
                entities=entities_list,
                claims=[],
                suspicious_phrases=observable_urgency,
                recommended_tools=recommended_tools or ["scam_analysis"],
                missing_information=[f"Meta inference encountered error: {str(e)}"],
            )
