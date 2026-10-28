"""TrustLens AI - Pytest Test Configuration and Fixtures"""

import asyncio
import os
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.api.deps import get_db
from app.core.config import settings
from app.db.models import Base
from app.main import app

TEST_DB_URL = "sqlite+aiosqlite:///./test_trustlens.db"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


import json

def custom_json_serializer(obj):
    return json.dumps(obj, default=str)


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(
        TEST_DB_URL,
        connect_args={"check_same_thread": False},
        json_serializer=custom_json_serializer,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    if os.path.exists("./test_trustlens.db"):
        try:
            os.remove("./test_trustlens.db")
        except Exception:
            pass


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncSession:
    SessionLocal = async_sessionmaker(bind=test_engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncClient:
    from app.core.security import verify_api_key

    async def override_get_db():
        yield db_session

    async def override_verify_api_key():
        return "test_authenticated_user"

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[verify_api_key] = override_verify_api_key

    transport = ASGITransport(app=app)
    headers = {"X-API-Key": settings.SECRET_KEY}
    async with AsyncClient(transport=transport, base_url="http://test", headers=headers) as ac:
        yield ac
    app.dependency_overrides.clear()
