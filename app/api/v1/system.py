"""TrustLens AI - System Health & Readiness Router

Exposes /health and /ready probes monitoring database and external service status.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.clients.meta_client import meta_client
from app.core.config import settings
from app.db.session import get_db
from app.schemas.investigation import HealthResponse, ReadinessResponse

router = APIRouter(tags=["System"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Liveness probe returning application operational status."""
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        timestamp=datetime.now(timezone.utc),
    )


@router.get("/ready", response_model=ReadinessResponse)
async def readiness_check(db: AsyncSession = Depends(get_db)):
    """Readiness probe verifying database health and external integration credentials."""
    # Check Database
    db_status = "ok"
    try:
        await db.execute(text("SELECT 1"))
    except Exception as e:
        db_status = f"unhealthy: {str(e)}"

    # Check Meta Model API
    meta_info = await meta_client.check_connectivity()

    # Provider configuration summary
    provider_flags = {
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "phishtank": bool(settings.PHISHTANK_API_KEY),
        "urlhaus": True,  # Public API available without mandatory key
        "google_factcheck": bool(settings.GOOGLE_FACTCHECK_API_KEY),
    }

    is_ready = (db_status == "ok")

    return ReadinessResponse(
        ready=is_ready,
        database=db_status,
        meta_model_api=meta_info,
        external_providers=provider_flags,
    )
