"""TrustLens AI - Agent B: Scam Detection

Identifies urgency, credential/OTP demands, coercive timelines, and social engineering patterns.
Every finding must cite an actual phrase from the input.
"""

from typing import Optional
from app.clients.meta_client import meta_client
from app.core.logging import logger
from app.core.security import isolate_untrusted_input
from app.schemas.agent_outputs import ScamDetectionOutput
from app.services.content_normalizer import ContentNormalizer


class ScamDetectionAgent:
    """Agent B: Scam Detection."""

    SYSTEM_PROMPT = (
        "You are Agent B (Scam Detection) for TrustLens AI.\n"
        "Your task is to analyze content for indicators of social engineering, fraud, and psychological manipulation.\n"
        "Check explicitly for:\n"
        "1. Urgency and pressure tactics.\n"
        "2. Demands for passwords, PINs, or One-Time Passwords (OTPs).\n"
        "3. Financial demands (wire transfer, cryptocurrency, gift cards, prepaid vouchers).\n"
        "4. Unrealistic rewards or coercive threats.\n"
        "5. Requests to bypass standard corporate verification.\n"
        "MANDATORY RULE: Every indicator must cite the actual phrase or observable feature from the input. "
        "Do NOT classify content as fraudulent based solely on suspicious tone without observable evidence."
    )

    @classmethod
    async def analyze(cls, text: str) -> ScamDetectionOutput:
        observable_urgency = ContentNormalizer.extract_observable_urgency(text)
        lower_text = text.lower()

        # Deterministic checks
        has_otp = any(w in lower_text for w in ["otp", "one-time password", "verification code", "security code", "2fa code", "passcode"])
        has_password = any(w in lower_text for w in ["password", "login credentials", "secret key", "seed phrase"])
        has_crypto_or_wire = any(w in lower_text for w in ["wire transfer", "bitcoin", "btc", "eth", "usdt", "gift card", "apple gift card", "zelle", "venmo", "transfer $", "wire", "transfer 2", "transfer $2"])
        has_extortion = any(w in lower_text for w in ["arrest warrant", "law enforcement", "fbi", "police", "jail", "legal action", "avoid arrest", "arrest", "sheriff"])
        has_family_lure = any(w in lower_text for w in ["dropped my phone", "temporary number", "hi mom", "hi dad"])

        threat_patterns = []
        if has_extortion:
            threat_patterns.append("threat of legal action or arrest warrant")
        if has_family_lure:
            threat_patterns.append("family emergency impersonation lure ('dropped phone')")

        payment_methods = [p for p in ["bitcoin", "wire transfer", "gift cards", "venmo", "zelle"] if p in lower_text]

        # Fallback if Meta Model API is not configured
        if not meta_client.is_configured:
            is_harvesting = has_otp or has_password
            is_financial = has_crypto_or_wire
            likelihood = "high" if (is_harvesting or has_extortion or (is_financial and observable_urgency)) else ("medium" if observable_urgency else "low")

            return ScamDetectionOutput(
                urgency_detected=bool(observable_urgency),
                urgency_indicators=observable_urgency,
                credential_or_otp_harvesting=is_harvesting,
                financial_demands=is_financial,
                payment_instructions=payment_methods,
                threat_or_reward_patterns=threat_patterns,
                social_engineering_tactics=(["extortion threat"] if has_extortion else []) + (["artificial urgency"] if observable_urgency else []),
                scam_likelihood=likelihood,
                observed_phrases=observable_urgency + threat_patterns + payment_methods,
                reasoning="Evaluated using deterministic keyword, extortion threat, and credential harvesting heuristic.",
            )

        messages = [
            {"role": "system", "content": cls.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Analyze this content for scam indicators:\n{isolate_untrusted_input(text, 'MESSAGE')}",
            },
        ]

        try:
            output, _ = await meta_client.generate_structured(
                messages=messages,
                schema=ScamDetectionOutput,
                temperature=0.1,
            )
            # Ensure deterministic findings are merged
            if has_otp or has_password:
                output.credential_or_otp_harvesting = True
            if observable_urgency:
                output.urgency_detected = True
                for u in observable_urgency:
                    if u not in output.urgency_indicators:
                        output.urgency_indicators.append(u)
            return output
        except Exception as e:
            logger.warning(f"Agent B structured inference error: {e}. Falling back to deterministic rules.")
            return ScamDetectionOutput(
                urgency_detected=bool(observable_urgency),
                urgency_indicators=observable_urgency,
                credential_or_otp_harvesting=has_otp or has_password,
                financial_demands=has_crypto_or_wire,
                scam_likelihood="high" if (has_otp or has_password) else "medium",
                observed_phrases=observable_urgency,
                reasoning=f"Fallback analysis applied due to inference error: {str(e)}",
            )
