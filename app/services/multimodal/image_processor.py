"""TrustLens AI - Multimodal Image & Screenshot Processor

Coordinates secure image validation, safe decoding, OCR extraction, Meta Muse Spark
multimodal reasoning, and correlation/reconciliation into a unified evidentiary result.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.clients.meta_client import meta_client
from app.core.config import settings
from app.core.logging import logger
from app.core.security import compute_sha256, isolate_untrusted_input, validate_image_bytes
from app.schemas.agent_outputs import (
    MetaVisionAnalysisSchema,
    OCRExtractionResult,
    ReconciledImageAnalysis,
)
from app.services.multimodal.image_reconciler import ImageReconciler
from app.services.multimodal.ocr_service import OCRService


class ImageAnalysisResult(BaseModel):
    sha256: str
    width: int
    height: int
    format: str
    mime_type: str
    extracted_text: str
    ocr_result: OCRExtractionResult
    meta_vision: Optional[MetaVisionAnalysisSchema] = None
    reconciled: ReconciledImageAnalysis
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_entities: List[Dict[str, Any]] = Field(default_factory=list)
    extracted_claims: List[Dict[str, Any]] = Field(default_factory=list)
    observed_brands: List[str] = Field(default_factory=list)
    is_screenshot: bool = True
    discrepancies: List[str] = Field(default_factory=list)


class ImageProcessor:
    """Production processor for uploaded screenshots and suspicious images."""

    VISION_PROMPT = (
        "You are TrustLens AI Vision Specialist. Analyze this submitted image or screenshot for digital safety, fraud, impersonation, or deceptive patterns.\n\n"
        "Requirements:\n"
        "1. Identify the apparent purpose or narrative of the screenshot.\n"
        "2. Strictly distinguish between what is visibly present in the image and any contextual inferences you make.\n"
        "3. Transcribe visible URLs, domain names, contact addresses, and payment instructions.\n"
        "4. Note any claimed organizations, logos, or brand badges.\n"
        "5. Identify any factual claims that require external verification.\n"
        "6. Explicitly record any ambiguities, blurred regions, or limitations.\n"
        "7. DO NOT claim the image is authentic or fraudulent based solely on visual appearance."
    )

    @classmethod
    async def process_image(
        cls,
        image_bytes: bytes,
        filename: str = "upload.png",
        mime_type: Optional[str] = None,
        context_notes: Optional[str] = None,
        sender_hint: Optional[str] = None,
    ) -> ImageAnalysisResult:
        """Validates, decodes, runs OCR and Meta AI vision, and reconciles findings."""
        # 1. Secure Image Validation & Safe Decoding (magic bytes, size, dimensions, metadata strip)
        img_format, detected_mime, width, height, sanitized_bytes = validate_image_bytes(
            image_bytes,
            allowed_types=settings.ALLOWED_IMAGE_TYPES,
            max_size_bytes=settings.MAX_UPLOAD_SIZE_BYTES,
        )

        sha256_hash = compute_sha256(sanitized_bytes)

        # 2. Run Optical Character Recognition (OCR)
        ocr_result: OCRExtractionResult = OCRService.extract_text(sanitized_bytes)

        # 3. Meta Muse Spark Multimodal Vision Inference
        meta_vision: Optional[MetaVisionAnalysisSchema] = None
        if meta_client.is_configured:
            try:
                prompt_text = cls.VISION_PROMPT
                if sender_hint:
                    prompt_text += f"\nClaimed sender hint provided by user: {sender_hint}"
                if context_notes:
                    prompt_text += f"\nContext notes provided: {context_notes}"

                meta_vision, _ = await meta_client.analyze_image_structured(
                    image_bytes=sanitized_bytes,
                    mime_type=detected_mime,
                    prompt=prompt_text,
                    schema=MetaVisionAnalysisSchema,
                    temperature=0.1,
                )
            except Exception as e:
                logger.warning(f"Meta vision analysis request failed: {e}")
                # Create fallback structured output recording the failure without hallucination
                meta_vision = MetaVisionAnalysisSchema(
                    apparent_purpose="Inconclusive (Meta Model API error)",
                    visible_elements=["Image decoded successfully"],
                    inferred_context=[],
                    suspicious_instructions=[],
                    claimed_sender_or_organization=sender_hint,
                    visible_urls=ocr_result.detected_urls,
                    payment_or_credential_requests=ocr_result.detected_payment_terms,
                    impersonation_indicators=[],
                    claims_requiring_verification=[],
                    ambiguities_and_limitations=[f"Meta vision inference unavailable: {str(e)}"],
                    raw_summary=f"Meta vision reasoning failed or timed out: {str(e)}",
                )
        else:
            # Deterministic, non-hallucinated fallback when credentials are not configured
            ambiguities = ["Meta Model API is not configured (MODEL_API_KEY missing); analysis based on OCR."]
            meta_vision = MetaVisionAnalysisSchema(
                apparent_purpose=f"Screenshot analysis for {filename}",
                visible_elements=[f"Image dimensions {width}x{height}, format {img_format}"],
                inferred_context=[],
                suspicious_instructions=ocr_result.detected_warnings,
                claimed_sender_or_organization=ocr_result.claimed_organizations[0] if ocr_result.claimed_organizations else sender_hint,
                visible_urls=ocr_result.detected_urls,
                payment_or_credential_requests=ocr_result.detected_payment_terms,
                impersonation_indicators=[],
                claims_requiring_verification=[f"Claim in image text: {w}" for w in ocr_result.detected_warnings],
                ambiguities_and_limitations=ambiguities,
                raw_summary=f"Image {filename} processed via OCR ({ocr_result.engine_used}). Meta vision model not configured.",
            )

        # 4. Reconcile OCR and Meta Vision Findings
        reconciled: ReconciledImageAnalysis = ImageReconciler.reconcile(
            ocr_result=ocr_result,
            meta_vision=meta_vision,
            image_sha256=sha256_hash,
        )

        # 5. Extract Entities and Claims for Orchestrator
        extracted_entities: List[Dict[str, Any]] = []
        for u in reconciled.all_urls:
            extracted_entities.append({"type": "url", "value": u, "context": "Extracted from image"})

        for em in ocr_result.detected_emails:
            extracted_entities.append({"type": "email", "value": em, "context": "Extracted from OCR"})

        for ph in ocr_result.detected_phones:
            extracted_entities.append({"type": "phone", "value": ph, "context": "Extracted from OCR"})

        if reconciled.primary_organization:
            extracted_entities.append({
                "type": "organization",
                "value": reconciled.primary_organization,
                "context": f"Claimed brand/organization (source: {reconciled.organization_source})",
            })

        extracted_claims: List[Dict[str, Any]] = []
        for c in reconciled.claims_to_verify:
            extracted_claims.append({"claim_text": c, "context": "Extracted from image content"})

        observed_brands = list(ocr_result.claimed_organizations)
        if meta_vision and meta_vision.claimed_sender_or_organization and meta_vision.claimed_sender_or_organization not in observed_brands:
            observed_brands.append(meta_vision.claimed_sender_or_organization)

        # Wrap reconciled text with prompt injection boundaries
        isolated_text = isolate_untrusted_input(reconciled.reconciled_text, context_label="IMAGE_EXTRACTED_CONTENT")

        return ImageAnalysisResult(
            sha256=sha256_hash,
            width=width,
            height=height,
            format=img_format,
            mime_type=detected_mime,
            extracted_text=isolated_text,
            ocr_result=ocr_result,
            meta_vision=meta_vision,
            reconciled=reconciled,
            extracted_urls=reconciled.all_urls,
            extracted_entities=extracted_entities,
            extracted_claims=extracted_claims,
            observed_brands=observed_brands,
            is_screenshot=True,
            discrepancies=reconciled.discrepancies,
        )
