"""TrustLens AI - Text Processor

Handles text message and email normalization, entity harvesting, and language detection hints.
"""

from typing import Any, Dict, List
from pydantic import BaseModel
from app.core.security import compute_sha256
from app.services.content_normalizer import ContentNormalizer


class TextProcessingResult(BaseModel):
    sha256: str
    cleaned_text: str
    entities: List[Dict[str, Any]]
    urgency_keywords: List[str]
    has_urls: bool
    has_financial_demands: bool


class TextProcessor:
    """Processes plain text, emails, and SMS messages."""

    @classmethod
    def process_text(cls, raw_text: str) -> TextProcessingResult:
        cleaned = raw_text.strip()
        sha256 = compute_sha256(cleaned.encode("utf-8"))

        entities = ContentNormalizer.extract_entities(cleaned)
        urgency = ContentNormalizer.extract_observable_urgency(cleaned)

        has_urls = any(e["type"] == "url" for e in entities)
        has_money = any(e["type"] in ("money", "crypto_address") for e in entities)

        return TextProcessingResult(
            sha256=sha256,
            cleaned_text=cleaned,
            entities=entities,
            urgency_keywords=urgency,
            has_urls=has_urls,
            has_financial_demands=has_money,
        )
