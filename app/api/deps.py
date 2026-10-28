"""TrustLens AI - FastAPI Dependencies

Provides shared dependencies for database sessions, repository access, and authentication.
"""

from typing import AsyncGenerator
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import verify_api_key
from app.db.repository import InvestigationRepository
from app.db.session import get_db


async def get_repository(db: AsyncSession = Depends(get_db)) -> InvestigationRepository:
    """Provides an initialized InvestigationRepository."""
    return InvestigationRepository(db)
