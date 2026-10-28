"""TrustLens AI - Multimodal Image & Screenshot Processor

Processes uploaded images/screenshots using Meta Muse Spark 1.3 multimodal input
and supplementary OCR where available.
"""

import base64
import io
from typing import Any, Dict, Optional
from PIL import Image
from pydantic import BaseModel
from app.clients.meta_client import meta_client
from app.core.logging import logger
from app.core.security import compute_sha256, isolate_untrusted_input


class ImageAnalysisResult(BaseModel):
    sha256: str
    width: int
    height: int
    format: str
    extracted_text: str
    ocr_text: Optional[str] = None
    observed_brands: list[str] = []
    observed_urls: list[str] = []
    is_screenshot: bool = False
    model_analysis: str = ""


class ImageProcessor:
    """Processes images and screenshots for TrustLens AI."""

    @classmethod
    async def process_image(cls, image_bytes: bytes, filename: str = "upload.png", mime_type: str = "image/png") -> ImageAnalysisResult:
        """Inspects image dimensions, computes hash, and analyzes content with Meta Muse Spark."""
        sha256 = compute_sha256(image_bytes)

        # 1. Validate image format and dimensions via Pillow
        try:
            pil_img = Image.open(io.BytesIO(image_bytes))
            width, height = pil_img.size
            img_format = pil_img.format or "UNKNOWN"
        except Exception as e:
            raise ValueError(f"Malformed or unsupported image file: {str(e)}")

        # 2. Supplementary OCR (attempt pytesseract if available, gracefully fallback)
        ocr_text: Optional[str] = None
        try:
            import pytesseract
            ocr_text = pytesseract.image_to_string(pil_img).strip()
        except Exception:
            # Tesseract binary not installed on OS or library missing; fallback is expected
            ocr_text = None

        # 3. Meta Muse Spark multimodal visual analysis
        b64_data = base64.b64encode(image_bytes).decode("utf-8")
        data_uri = f"data:{mime_type};base64,{b64_data}"

        prompt = (
            "You are TrustLens AI Vision Specialist. Analyze this submitted image or screenshot for digital safety, fraud, or impersonation.\n"
            "Examine carefully:\n"
            "1. Any visible text (transcribe it thoroughly).\n"
            "2. Any URLs, domain names, phone numbers, or email addresses.\n"
            "3. Any company logos, brands, or claimed organizations.\n"
            "4. Visual signs of spoofed UI, phishing templates, fake security alerts, or social engineering.\n"
            "Return a concise factual summary of observable visual elements."
        )

        model_analysis = ""
        observed_brands = []
        observed_urls = []
        is_screenshot = True

        if meta_client.is_configured:
            try:
                messages = [
                    {
                        "role": "user",
                        "content": [
                            {"type": "text", "text": prompt},
                            {"type": "image_url", "image_url": {"url": data_uri}},
                        ],
                    }
                ]
                resp = await meta_client.generate_reasoning(messages=messages, temperature=0.1)
                model_analysis = resp.content.strip()
            except Exception as e:
                logger.warning(f"Meta visual reasoning failed or unavailable: {e}")
                model_analysis = f"Meta vision inference was unavailable: {str(e)}"
        else:
            model_analysis = "Meta Model API key not configured for vision inference."

        # Combine extracted text
        extracted_text = (ocr_text or "") + "\n" + model_analysis

        return ImageAnalysisResult(
            sha256=sha256,
            width=width,
            height=height,
            format=img_format,
            extracted_text=extracted_text.strip(),
            ocr_text=ocr_text,
            observed_brands=observed_brands,
            observed_urls=observed_urls,
            is_screenshot=is_screenshot,
            model_analysis=model_analysis,
        )
