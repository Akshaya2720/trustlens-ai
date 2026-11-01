"""TrustLens AI - Optical Character Recognition (OCR) Service

Production-grade OCR service using RapidOCR (PaddleOCR ONNX engine) with
Pytesseract fallback. Extracts visible text, bounding boxes, word/line-level
confidence scoring, and structured entity harvesting (URLs, emails, phones,
payment instructions, account warnings, organizations, timestamps).
"""

import io
import re
from typing import Any, Dict, List, Optional, Tuple
from PIL import Image
from app.core.config import settings
from app.core.logging import logger
from app.schemas.agent_outputs import OCRExtractionResult
from app.services.content_normalizer import URL_PATTERN
from app.services.safe_url import SafeURLInspector

# Regex patterns for OCR entity extraction
EMAIL_PATTERN = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
PHONE_PATTERN = re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b")
TIMESTAMP_PATTERN = re.compile(
    r"\b(?:\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM|am|pm)?|"
    r"\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{1,2}(?:st|nd|rd|th)?,?\s*\d{2,4}?|"
    r"\d+\s+(?:min|mins|minute|minutes|hour|hours|day|days|sec|seconds)\s+ago)\b",
    re.IGNORECASE,
)

PAYMENT_TERMS = [
    "gift card", "apple gift card", "itunes", "steam card", "google play card",
    "bitcoin", "btc", "ethereum", "eth", "usdt", "crypto", "wallet",
    "wire transfer", "bank wire", "zelle", "venmo", "cashapp", "cash app",
    "western union", "moneygram", "direct deposit", "routing number",
    "account number", "cvv", "credit card", "debit card",
]

WARNING_TERMS = [
    "account suspended", "account locked", "unauthorized access", "security alert",
    "immediate action required", "urgent", "action required", "verify your identity",
    "unusual activity", "compromised", "temporarily restricted", "within 24 hours",
    "warrant for your arrest", "legal action", "order confirmed", "invoice attached",
]

KNOWN_ORGANIZATIONS = [
    "paypal", "apple", "microsoft", "amazon", "netflix", "wells fargo", "chase",
    "bank of america", "citi", "citibank", "irs", "geek squad", "mcafee", "norton",
    "dhl", "fedex", "usps", "ups", "meta", "facebook", "instagram", "whatsapp",
    "coinbase", "binance", "walmart", "target", "ebay",
]

BRAND_CANONICAL = {
    "paypal": "PayPal",
    "apple": "Apple",
    "microsoft": "Microsoft",
    "amazon": "Amazon",
    "netflix": "Netflix",
    "wells fargo": "Wells Fargo",
    "chase": "Chase",
    "bank of america": "Bank of America",
    "citi": "Citi",
    "citibank": "Citibank",
    "irs": "IRS",
    "geek squad": "Geek Squad",
    "mcafee": "McAfee",
    "norton": "Norton",
    "dhl": "DHL",
    "fedex": "FedEx",
    "usps": "USPS",
    "ups": "UPS",
    "meta": "Meta",
    "facebook": "Facebook",
    "instagram": "Instagram",
    "whatsapp": "WhatsApp",
    "coinbase": "Coinbase",
    "binance": "Binance",
    "walmart": "Walmart",
    "target": "Target",
    "ebay": "eBay",
}


class OCRService:
    """Manages OCR text extraction, confidence metrics, and structured parsing."""

    _rapidocr_engine = None
    _engine_initialized = False

    @classmethod
    def _get_rapidocr(cls):
        """Lazy-loads and caches RapidOCR ONNX engine."""
        if not cls._engine_initialized:
            try:
                from rapidocr_onnxruntime import RapidOCR
                cls._rapidocr_engine = RapidOCR()
                logger.info("RapidOCR ONNX engine successfully initialized.")
            except Exception as e:
                logger.warning(f"RapidOCR engine initialization failed: {e}")
                cls._rapidocr_engine = None
            cls._engine_initialized = True
        return cls._rapidocr_engine

    @classmethod
    def extract_text(cls, image_bytes: bytes) -> OCRExtractionResult:
        """Extracts visible text, line confidence, and features from an image.

        Gracefully tries RapidOCR first, then pytesseract, or handles empty/corrupted data.
        """
        lines_data: List[Dict[str, Any]] = []
        raw_text_parts: List[str] = []
        confidences: List[float] = []
        engine_used = "none"
        engine_status = "ok"

        # 1. Attempt RapidOCR
        rapid_engine = cls._get_rapidocr()
        if rapid_engine is not None:
            try:
                ocr_res, _ = rapid_engine(image_bytes)
                if ocr_res:
                    engine_used = "rapidocr"
                    for item in ocr_res:
                        # item format: [box, text, confidence]
                        box = item[0]
                        text = str(item[1]).strip()
                        conf = float(item[2])
                        if text:
                            raw_text_parts.append(text)
                            confidences.append(conf)
                            lines_data.append({
                                "text": text,
                                "confidence": round(conf, 4),
                                "box": box,
                            })
            except Exception as e:
                logger.warning(f"RapidOCR extraction failed: {e}")

        # 2. Fallback to pytesseract if RapidOCR was not used or yielded nothing
        if not raw_text_parts:
            try:
                import pytesseract
                if settings.TESSERACT_CMD:
                    pytesseract.pytesseract.tesseract_cmd = settings.TESSERACT_CMD

                with Image.open(io.BytesIO(image_bytes)) as pil_img:
                    data_dict = pytesseract.image_to_data(pil_img, output_type=pytesseract.Output.DICT)

                    n_boxes = len(data_dict.get("text", []))
                    current_line: List[str] = []
                    current_conf: List[float] = []

                    for i in range(n_boxes):
                        t = data_dict["text"][i].strip()
                        c = float(data_dict["conf"][i])
                        if t and c >= 0:
                            current_line.append(t)
                            current_conf.append(c / 100.0)

                    if current_line:
                        engine_used = "tesseract"
                        full_tess_text = " ".join(current_line)
                        raw_text_parts.append(full_tess_text)
                        confidences.extend(current_conf)
                        lines_data.append({
                            "text": full_tess_text,
                            "confidence": round(sum(current_conf) / max(1, len(current_conf)), 4),
                            "box": [],
                        })
            except Exception as e:
                logger.debug(f"Pytesseract fallback unavailable: {e}")

        # If still no text extracted
        if not raw_text_parts:
            return OCRExtractionResult(
                raw_text="",
                confidence=0.0,
                min_confidence=0.0,
                word_count=0,
                lines=[],
                detected_urls=[],
                detected_emails=[],
                detected_phones=[],
                detected_payment_terms=[],
                detected_warnings=[],
                claimed_organizations=[],
                detected_timestamps=[],
                is_low_confidence=True,
                engine_used=engine_used,
                engine_status="empty",
            )

        full_raw_text = "\n".join(raw_text_parts)
        avg_conf = sum(confidences) / len(confidences) if confidences else 0.0
        min_conf = min(confidences) if confidences else 0.0
        is_low_conf = avg_conf < settings.OCR_MIN_CONFIDENCE_THRESHOLD

        if is_low_conf:
            engine_status = "low_confidence"

        # Structured feature parsing with OCR noise resilience
        # 1. Clean common OCR spacing/punctuation artifacts for URL/email detection
        cleaned_for_urls = full_raw_text
        # Separate protocol if attached to preceding word (e.g. Visithttps:// -> Visit https://)
        cleaned_for_urls = re.sub(r"([a-zA-Z0-9])(https?[:;]?//|www\.)", r"\1 \2", cleaned_for_urls, flags=re.IGNORECASE)
        # Fix missing colon in http(s)//
        cleaned_for_urls = re.sub(r"\b(https?)\s*[:;]?\s*//", r"\1://", cleaned_for_urls, flags=re.IGNORECASE)
        # Fix spaces around dots in domains e.g. "paypal . com" or "paypal. com"
        cleaned_for_urls = re.sub(r"([a-zA-Z0-9_-]+)\s*\.\s*([a-zA-Z]{2,})", r"\1.\2", cleaned_for_urls)
        # Separate trailing words concatenated to TLD (e.g. .comtoverify -> .com toverify)
        tlds_pattern = "online|site|club|info|tech|shop|app|top|xyz|com|org|net|biz|edu|gov|io|me|co"
        cleaned_for_urls = re.sub(rf"(\.(?:{tlds_pattern}))([a-zA-Z]{{2,}})", r"\1 \2", cleaned_for_urls, flags=re.IGNORECASE)

        detected_urls = []
        for match in URL_PATTERN.finditer(cleaned_for_urls):
            raw_url = match.group(0).rstrip(".,;:!?)")
            norm_url = SafeURLInspector.normalize_url(raw_url)
            if norm_url not in detected_urls:
                detected_urls.append(norm_url)

        # Also search for bare domains with standard TLDs (e.g. secure-login.com)
        bare_domain_pattern = re.compile(
            r"(?<![a-zA-Z0-9@.-])([a-zA-Z0-9][a-zA-Z0-9-]{2,61}[a-zA-Z0-9]\.(?:com|org|net|edu|gov|xyz|top|io|info|biz|club|site|online|me|co))\b",
            re.IGNORECASE,
        )
        for match in bare_domain_pattern.finditer(cleaned_for_urls):
            dom = match.group(1)
            # Avoid extracting email domain fragments if preceded by @
            if "@" in dom:
                continue
            norm_dom = SafeURLInspector.normalize_url(f"https://{dom}")
            if norm_dom not in detected_urls:
                detected_urls.append(norm_dom)

        # Cleaned email detection (handles spaces around @ or in handle)
        cleaned_for_emails = re.sub(r"\s*@\s*", "@", full_raw_text)
        cleaned_for_emails = re.sub(r"([a-zA-Z0-9_.+-]+)\s*\.\s*([a-zA-Z]{2,})", r"\1.\2", cleaned_for_emails)
        detected_emails = list(set(EMAIL_PATTERN.findall(cleaned_for_emails)))

        # Phones
        raw_phones = PHONE_PATTERN.findall(full_raw_text)
        detected_phones = [p.strip() for p in set(raw_phones) if len(re.sub(r"\D", "", p)) >= 7]

        # Payment terms
        lower_text = full_raw_text.lower()
        detected_payments = [t for t in PAYMENT_TERMS if t in lower_text]

        # Warnings
        detected_warnings = [w for w in WARNING_TERMS if w in lower_text]

        # Claimed Organizations
        detected_orgs = []
        for org in KNOWN_ORGANIZATIONS:
            if re.search(r"\b" + re.escape(org) + r"\b", lower_text) or org in lower_text:
                canonical = BRAND_CANONICAL.get(org, org.title())
                if canonical not in detected_orgs:
                    detected_orgs.append(canonical)

        # Timestamps
        detected_timestamps = list(set(TIMESTAMP_PATTERN.findall(full_raw_text)))

        return OCRExtractionResult(
            raw_text=full_raw_text,
            confidence=round(avg_conf, 3),
            min_confidence=round(min_conf, 3),
            word_count=len(full_raw_text.split()),
            lines=lines_data,
            detected_urls=detected_urls,
            detected_emails=detected_emails,
            detected_phones=detected_phones,
            detected_payment_terms=detected_payments,
            detected_warnings=detected_warnings,
            claimed_organizations=detected_orgs,
            detected_timestamps=detected_timestamps,
            is_low_confidence=is_low_conf,
            engine_used=engine_used,
            engine_status=engine_status,
        )
