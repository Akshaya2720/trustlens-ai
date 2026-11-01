"""TrustLens AI - Production Rate Limiter & Security Headers Middleware (Phase 10)

Provides:
1. Thread-safe sliding-window rate limiting per client IP or API key.
2. Standard HTTP 429 Too Many Requests response with 'Retry-After' and 'X-RateLimit-*' headers.
3. Security headers middleware enforcing OWASP/NIST web application security baselines.
"""

import time
from collections import defaultdict
from threading import Lock
from typing import Dict, List, Optional, Set
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from app.core.config import settings
from app.core.logging import logger


class InMemoryRateLimiter:
    """Thread-safe sliding-window in-memory rate limiter."""

    def __init__(self, requests_per_minute: int = 60, window_seconds: int = 60):
        self.requests_per_minute = requests_per_minute
        self.window_seconds = window_seconds
        self._history: Dict[str, List[float]] = defaultdict(list)
        self._lock = Lock()
        self._whitelist: Set[str] = set()

    def add_whitelist(self, key: str) -> None:
        with self._lock:
            self._whitelist.add(key)

    def is_rate_limited(self, client_key: str) -> tuple[bool, int, int]:
        """Checks if client exceeded allowed requests.

        Returns: (is_limited, remaining_quota, retry_after_seconds)
        """
        now = time.time()
        with self._lock:
            if client_key in self._whitelist:
                return False, self.requests_per_minute, 0

            # Prune timestamps older than window
            timestamps = self._history[client_key]
            cutoff = now - self.window_seconds
            valid_timestamps = [t for t in timestamps if t > cutoff]
            self._history[client_key] = valid_timestamps

            if len(valid_timestamps) >= self.requests_per_minute:
                oldest = valid_timestamps[0]
                retry_after = max(1, int(oldest + self.window_seconds - now))
                return True, 0, retry_after

            # Record this request
            self._history[client_key].append(now)
            remaining = self.requests_per_minute - len(self._history[client_key])
            return False, remaining, 0

    def reset(self) -> None:
        """Resets all tracking histories (used for testing)."""
        with self._lock:
            self._history.clear()


# Global rate limiter instance
rate_limiter = InMemoryRateLimiter(requests_per_minute=60, window_seconds=60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware enforcing sliding-window rate limits per client."""

    EXCLUDED_PREFIXES = ("/health", "/ready", "/docs", "/redoc", "/openapi.json")

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Bypass rate limits for health and docs probes
        path = request.url.path
        if any(path.startswith(prefix) for prefix in self.EXCLUDED_PREFIXES):
            return await call_next(request)

        # Extract client key: Prefer X-API-Key, fallback to client IP
        client_key = request.headers.get("X-API-Key")
        if not client_key:
            client_key = request.client.host if request.client else "127.0.0.1"

        is_limited, remaining, retry_after = rate_limiter.is_rate_limited(client_key)
        if is_limited:
            logger.warning(f"Rate limit exceeded for client '{client_key}' on {request.method} {path}")
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "RateLimitExceeded",
                    "message": "Rate limit exceeded. Too many requests submitted. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(rate_limiter.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                },
            )

        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(rate_limiter.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware enforcing OWASP-recommended HTTP security headers on all responses."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none';"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response
