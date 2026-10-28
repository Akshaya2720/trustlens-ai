"""TrustLens AI - Structured Logging & PII Redaction

Provides structured logging with automatic redaction of sensitive tokens,
API keys, credentials, and identifiable user data.
"""

import logging
import re
import sys
from typing import Any
from app.core.config import settings

# Regex patterns for sensitive data redaction
REDACTION_PATTERNS = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(api[_\-]?key\s*[:=]\s*['\"]?)[A-Za-z0-9_\-\.]{8,}(['\"]?)", re.IGNORECASE), r"\1[REDACTED]\2"),
    (re.compile(r"(x-apikey\s*[:=]\s*['\"]?)[A-Za-z0-9_\-\.]{8,}(['\"]?)", re.IGNORECASE), r"\1[REDACTED]\2"),
    (re.compile(r"(password\s*[:=]\s*['\"]?)[^\s'\"]+(['\"]?)", re.IGNORECASE), r"\1[REDACTED]\2"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"), "[EMAIL_REDACTED]"),
    (re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE_REDACTED]"),
]


class RedactingFormatter(logging.Formatter):
    """Custom log formatter that scrubs sensitive credentials and PII."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        if not settings.REDACT_PII_IN_LOGS:
            return original

        scrubbed = original
        for pattern, replacement in REDACTION_PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        return scrubbed


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configures structured, sanitized logging."""
    logger = logging.getLogger("trustlens")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Avoid duplicate handlers if reconfigured
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(getattr(logging, level.upper(), logging.INFO))
        formatter = RedactingFormatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    return logger


logger = setup_logging(level="DEBUG" if settings.DEBUG else "INFO")
