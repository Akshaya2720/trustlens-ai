"""TrustLens AI - Image Analysis Reconciliation Module

Correlates and compares OCR extraction with Meta AI multimodal vision reasoning.
Identifies corroborated URLs, discrepancies, ambiguous regions, and claims
requiring verification without discarding or silently resolving conflicting evidence.
"""

from typing import List, Optional
from app.core.logging import logger
from app.core.security import detect_prompt_injection
from app.schemas.agent_outputs import (
    MetaVisionAnalysisSchema,
    OCRExtractionResult,
    ReconciledImageAnalysis,
)
from app.services.safe_url import SafeURLInspector


class ImageReconciler:
    """Reconciles OCR-extracted content with Meta AI visual analysis."""

    @classmethod
    def reconcile(
        cls,
        ocr_result: OCRExtractionResult,
        meta_vision: Optional[MetaVisionAnalysisSchema],
        image_sha256: str = "",
    ) -> ReconciledImageAnalysis:
        discrepancies: List[str] = []
        ambiguous_regions: List[str] = []
        claims_to_verify: List[str] = []
        reconciliation_notes: List[str] = []

        # 1. URL Reconciliation and Deduplication
        ocr_urls = [SafeURLInspector.normalize_url(u) for u in ocr_result.detected_urls if u]
        meta_urls = []
        if meta_vision and meta_vision.visible_urls:
            for u in meta_vision.visible_urls:
                try:
                    norm = SafeURLInspector.normalize_url(u)
                    if norm not in meta_urls:
                        meta_urls.append(norm)
                except Exception:
                    pass

        # Identify overlap and unique URLs
        urls_corroborated = [u for u in ocr_urls if u in meta_urls]
        urls_ocr_only = [u for u in ocr_urls if u not in meta_urls]
        urls_meta_only = [u for u in meta_urls if u not in ocr_urls]

        all_urls = list(urls_corroborated)
        for u in urls_ocr_only:
            if u not in all_urls:
                all_urls.append(u)
        for u in urls_meta_only:
            if u not in all_urls:
                all_urls.append(u)

        if urls_corroborated:
            reconciliation_notes.append(
                f"Corroborated URLs ({len(urls_corroborated)}) found by both OCR and Meta vision: {', '.join(urls_corroborated)}"
            )
        if urls_ocr_only:
            reconciliation_notes.append(
                f"URLs detected exclusively by OCR ({len(urls_ocr_only)}): {', '.join(urls_ocr_only)}"
            )
        if urls_meta_only:
            reconciliation_notes.append(
                f"URLs identified exclusively by Meta visual model ({len(urls_meta_only)}): {', '.join(urls_meta_only)}"
            )

        # 2. Organization Identification & Discrepancies
        ocr_orgs = [o.lower() for o in ocr_result.claimed_organizations]
        meta_org = meta_vision.claimed_sender_or_organization.strip() if meta_vision and meta_vision.claimed_sender_or_organization else None
        meta_org_lower = meta_org.lower() if meta_org else None

        primary_org: Optional[str] = None
        org_source: str = "none"

        if meta_org_lower and ocr_orgs:
            # Check for agreement or conflict
            matches = [o for o in ocr_orgs if o in meta_org_lower or meta_org_lower in o]
            if matches:
                primary_org = meta_org
                org_source = "both"
            else:
                primary_org = meta_org
                org_source = "meta"
                discrepancies.append(
                    f"Claimed organization discrepancy: OCR detected '{', '.join(ocr_result.claimed_organizations)}' "
                    f"while visual model identified '{meta_org}'."
                )
        elif meta_org:
            primary_org = meta_org
            org_source = "meta"
        elif ocr_orgs:
            primary_org = ocr_result.claimed_organizations[0]
            org_source = "ocr"

        # 3. Content and Threat Discrepancies
        if meta_vision:
            # Check payment request discrepancies
            has_ocr_payment = bool(ocr_result.detected_payment_terms)
            has_meta_payment = bool(meta_vision.payment_or_credential_requests)
            if has_ocr_payment and not has_meta_payment:
                discrepancies.append(
                    f"Payment indicators discrepancy: OCR identified payment terminology "
                    f"({', '.join(ocr_result.detected_payment_terms)}), but visual model did not flag payment requests."
                )
            elif has_meta_payment and not has_ocr_payment:
                reconciliation_notes.append(
                    f"Visual model identified payment/credential requests not explicitly captured in OCR keywords: "
                    f"{'; '.join(meta_vision.payment_or_credential_requests)}"
                )

            # Check urgency/warning discrepancies
            has_ocr_warning = bool(ocr_result.detected_warnings)
            has_meta_instructions = bool(meta_vision.suspicious_instructions)
            if has_ocr_warning and not has_meta_instructions and meta_vision.apparent_purpose.lower() in ("normal", "benign", "informational"):
                discrepancies.append(
                    f"Urgency assessment discrepancy: OCR detected urgent warning text "
                    f"({', '.join(ocr_result.detected_warnings)}), whereas visual model classified purpose as benign."
                )

        # 4. Ambiguous Regions and Image Resolution Notes
        if ocr_result.is_low_confidence:
            ambiguous_regions.append(
                f"Low OCR confidence ({ocr_result.confidence:.2f} mean score); image may contain blurred, low-resolution, or stylized fonts."
            )
        if ocr_result.engine_status == "empty":
            ambiguous_regions.append("OCR engine detected no readable text lines in the uploaded image.")

        if meta_vision and meta_vision.ambiguities_and_limitations:
            for amb in meta_vision.ambiguities_and_limitations:
                if amb not in ambiguous_regions:
                    ambiguous_regions.append(amb)

        # 5. Claims Requiring External Verification
        if meta_vision and meta_vision.claims_requiring_verification:
            for claim in meta_vision.claims_requiring_verification:
                if claim not in claims_to_verify:
                    claims_to_verify.append(claim)

        # Check for claims in OCR text if not already covered
        if ocr_result.detected_warnings:
            warning_claim = f"Claim of urgent security warning or account restriction: {', '.join(ocr_result.detected_warnings)}"
            if warning_claim not in claims_to_verify:
                claims_to_verify.append(warning_claim)

        # 6. Prompt Injection Defense in Image
        injections = detect_prompt_injection(ocr_result.raw_text)
        if injections:
            discrepancies.append(
                f"Adversarial prompt injection pattern detected in image text ({len(injections)} signature(s)); isolated from execution."
            )

        # Compose reconciled text
        reconciled_text_parts = []
        if ocr_result.raw_text:
            reconciled_text_parts.append(f"[Visible OCR Text (Confidence: {ocr_result.confidence:.2f})]:\n{ocr_result.raw_text}")
        if meta_vision and meta_vision.raw_summary:
            reconciled_text_parts.append(f"[Visual Model Interpretation]:\n{meta_vision.raw_summary}")
            if meta_vision.apparent_purpose:
                reconciled_text_parts.append(f"Apparent Purpose: {meta_vision.apparent_purpose}")
            if meta_vision.suspicious_instructions:
                reconciled_text_parts.append("Suspicious Instructions: " + "; ".join(meta_vision.suspicious_instructions))

        reconciled_text = "\n\n".join(reconciled_text_parts)

        return ReconciledImageAnalysis(
            all_urls=all_urls,
            urls_corroborated=urls_corroborated,
            urls_ocr_only=urls_ocr_only,
            urls_meta_only=urls_meta_only,
            discrepancies=discrepancies,
            ambiguous_regions=ambiguous_regions,
            claims_to_verify=claims_to_verify,
            primary_organization=primary_org,
            organization_source=org_source,
            reconciled_text=reconciled_text,
            ocr_confidence=ocr_result.confidence,
            is_ocr_uncertain=ocr_result.is_low_confidence,
            image_sha256=image_sha256,
            reconciliation_notes=reconciliation_notes,
        )

