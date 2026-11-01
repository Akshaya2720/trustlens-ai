"""TrustLens AI - Content Normalization & Entity Extraction

Extracts URLs, email addresses, phone numbers, monetary values, crypto addresses,
and candidate claims using deterministic regex and pattern matching.
"""

import re
from typing import Any, Dict, List
from urllib.parse import urlparse
from app.services.safe_url import SafeURLInspector

# Regex Patterns
URL_PATTERN = re.compile(
    r"\b(?:https?://|www\.)[a-zA-Z0-9.\-_]+(?:\.[a-zA-Z]{2,})+(?:/[^\s<>'\"]*)?",
    re.IGNORECASE,
)
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
)
PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
MONEY_PATTERN = re.compile(
    r"(?:\$|€|£|₹|USD|EUR|GBP)\s*[\d,]+(?:\.\d{1,2})?|\b[\d,]+(?:\.\d{1,2})?\s*(?:dollars|euros|pounds|rupees|usd|inr|crypto|btc|eth|usdt)\b",
    re.IGNORECASE,
)
CRYPTO_PATTERN = re.compile(
    r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b"
)

# Common scam and urgency keyword triggers
URGENCY_KEYWORDS = [
    "urgent", "urgently", "immediately", "account suspended", "act now", "24 hours", "2 hours",
    "unauthorized access", "wire transfer", "gift card", "verification code",
    "one-time password", "otp", "password reset", "tax refund", "law enforcement",
    "arrest warrant", "lottery winner", "crypto investment", "double your money",
    "dropped my phone", "temporary number", "new number", "hi mom", "hi dad"
]

EXTORTION_LAW_KEYWORDS = [
    "arrest warrant", "law enforcement", "fbi", "irs notice", "police",
    "court order", "legal action", "jail time"
]

SUSPICIOUS_EXTENSIONS = [
    ".exe", ".bin", ".scr", ".bat", ".vbs", ".apk", ".dmg", ".iso", ".dll"
]



class ContentNormalizer:
    """Normalizes submitted content and extracts observable entities."""
    URL_PATTERN = URL_PATTERN
    EMAIL_PATTERN = EMAIL_PATTERN
    PHONE_PATTERN = PHONE_PATTERN
    MONEY_PATTERN = MONEY_PATTERN
    CRYPTO_PATTERN = CRYPTO_PATTERN

    @classmethod
    def extract_entities(cls, text: str) -> List[Dict[str, Any]]:
        """Extracts URLs, emails, phones, money, and crypto addresses from text."""
        entities: List[Dict[str, Any]] = []
        seen_values = set()

        # 1. URLs
        for match in URL_PATTERN.finditer(text):
            raw_url = match.group(0).rstrip(".,;:!?)")
            norm_url = SafeURLInspector.normalize_url(raw_url)
            if norm_url not in seen_values:
                seen_values.add(norm_url)
                entities.append({
                    "type": "url",
                    "value": norm_url,
                    "context": text[max(0, match.start() - 30) : min(len(text), match.end() + 30)],
                })

        # 2. Emails
        for match in EMAIL_PATTERN.finditer(text):
            email = match.group(0).lower()
            if email not in seen_values:
                seen_values.add(email)
                entities.append({
                    "type": "email",
                    "value": email,
                    "context": text[max(0, match.start() - 30) : min(len(text), match.end() + 30)],
                })

        # 3. Phone Numbers
        for match in PHONE_PATTERN.finditer(text):
            phone = match.group(0).strip()
            if phone not in seen_values:
                seen_values.add(phone)
                entities.append({
                    "type": "phone",
                    "value": phone,
                    "context": text[max(0, match.start() - 30) : min(len(text), match.end() + 30)],
                })

        # 4. Monetary Amounts
        for match in MONEY_PATTERN.finditer(text):
            val = match.group(0).strip()
            if val not in seen_values:
                seen_values.add(val)
                entities.append({
                    "type": "money",
                    "value": val,
                    "context": text[max(0, match.start() - 30) : min(len(text), match.end() + 30)],
                })

        # 5. Crypto Addresses
        for match in CRYPTO_PATTERN.finditer(text):
            val = match.group(0).strip()
            if val not in seen_values:
                seen_values.add(val)
                entities.append({
                    "type": "crypto_address",
                    "value": val,
                    "context": text[max(0, match.start() - 30) : min(len(text), match.end() + 30)],
                })

        return entities

    @classmethod
    def extract_observable_urgency(cls, text: str) -> List[str]:
        """Detects explicitly observable urgency or social engineering keywords."""
        lower_text = text.lower()
        found = []
        for kw in URGENCY_KEYWORDS:
            if kw in lower_text:
                found.append(kw)
        return found
