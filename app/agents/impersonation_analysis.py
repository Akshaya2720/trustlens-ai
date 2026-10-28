"""TrustLens AI - Agent C: Impersonation Analysis

Examines claimed identities and organizations against actual sender addresses,
links, domain registrations, and known legitimate domain patterns.
"""

from typing import List, Optional
from urllib.parse import urlparse
from app.clients.meta_client import meta_client
from app.core.logging import logger
from app.core.security import isolate_untrusted_input
from app.schemas.agent_outputs import ImpersonationAnalysisOutput

# Known legitimate corporate brand domains
WELL_KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "google": "google.com",
    "microsoft": "microsoft.com",
    "amazon": "amazon.com",
    "chase": "chase.com",
    "bank of america": "bankofamerica.com",
    "wells fargo": "wellsfargo.com",
    "netflix": "netflix.com",
    "meta": "meta.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "usps": "usps.com",
    "fedex": "fedex.com",
    "dhl": "dhl.com",
    "irs": "irs.gov",
}


class ImpersonationAnalysisAgent:
    """Agent C: Impersonation Analysis."""

    SYSTEM_PROMPT = (
        "You are Agent C (Impersonation Analysis) for TrustLens AI.\n"
        "Analyze whether the content attempts to impersonate a brand, institution, or executive.\n"
        "Check for discrepancies between the claimed brand and actual sender domains or URLs.\n"
        "RULE: Do NOT claim to verify a person's physical identity from a name or writing style alone.\n"
        "Evaluate specifically if the domain/URL mismatches the legitimate organization domain."
    )

    @classmethod
    async def analyze(
        cls,
        text: str,
        sender_hint: Optional[str] = None,
        extracted_urls: Optional[List[str]] = None,
    ) -> ImpersonationAnalysisOutput:
        extracted_urls = extracted_urls or []
        lower_text = text.lower()

        # Step 1: Detect claimed brand from text or sender_hint
        claimed_org = None
        official_domain = None
        for brand, domain in WELL_KNOWN_BRANDS.items():
            if brand in lower_text or (sender_hint and brand in sender_hint.lower()):
                claimed_org = brand.title()
                official_domain = domain
                break

        # Check domain mismatch across extracted URLs
        is_mismatch = False
        inconsistencies = []
        observed_host = None

        if claimed_org and official_domain and extracted_urls:
            for u in extracted_urls:
                parsed = urlparse(u)
                host = (parsed.hostname or "").lower()
                observed_host = host
                if host and not host.endswith(official_domain) and host != official_domain:
                    is_mismatch = True
                    inconsistencies.append(
                        f"Message claims to be from {claimed_org} (official domain: {official_domain}), "
                        f"but link directs to suspicious destination domain '{host}'."
                    )

        # Fallback if Meta Model API is not configured
        if not meta_client.is_configured:
            return ImpersonationAnalysisOutput(
                claimed_organization=claimed_org,
                sender_domain_or_address=observed_host or sender_hint,
                is_domain_mismatch=is_mismatch,
                brand_spoofing_indicators=["domain mismatch with well-known brand"] if is_mismatch else [],
                inconsistencies=inconsistencies,
                official_domain_candidate=official_domain,
                reasoning="Evaluated with brand keyword and domain alignment rules.",
            )

        messages = [
            {"role": "system", "content": cls.SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Check for brand or identity impersonation:\n"
                    f"{isolate_untrusted_input(text, 'CONTENT')}\n"
                    f"Sender Hint: {sender_hint or 'None'}\n"
                    f"Associated URLs: {extracted_urls}"
                ),
            },
        ]

        try:
            output, _ = await meta_client.generate_structured(
                messages=messages,
                schema=ImpersonationAnalysisOutput,
                temperature=0.1,
            )
            # Ensure deterministic domain mismatches are preserved
            if is_mismatch:
                output.is_domain_mismatch = True
                output.inconsistencies.extend(inconsistencies)
            if official_domain and not output.official_domain_candidate:
                output.official_domain_candidate = official_domain
            return output
        except Exception as e:
            logger.warning(f"Agent C structured inference error: {e}. Falling back to deterministic rules.")
            return ImpersonationAnalysisOutput(
                claimed_organization=claimed_org,
                sender_domain_or_address=observed_host or sender_hint,
                is_domain_mismatch=is_mismatch,
                brand_spoofing_indicators=["domain mismatch with well-known brand"] if is_mismatch else [],
                inconsistencies=inconsistencies,
                official_domain_candidate=official_domain,
                reasoning=f"Fallback analysis applied due to inference error: {str(e)}",
            )
