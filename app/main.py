"""TrustLens AI - FastAPI Application Entrypoint

Production-ready agentic AI backend for multimodal digital safety investigations.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api.v1.investigations import router as investigations_router
from app.api.v1.system import router as system_router
from app.core.config import settings
from app.core.logging import logger
from app.db.session import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan managing startup and shutdown tasks."""
    logger.info(f"Starting {settings.APP_NAME} v{settings.APP_VERSION} (Env: {settings.ENVIRONMENT})")
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Failed to initialize database during startup: {e}")
    yield
    logger.info(f"Shutting down {settings.APP_NAME}")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "TrustLens AI is an automated multimodal digital safety investigation backend. "
        "It coordinates specialized agentic workflows via LangGraph, integrates the official Meta Model API "
        "(Muse Spark 1.3 & Muse Voice Transcribe), retrieves external independent evidence "
        "(VirusTotal, URLhaus, PhishTank, Google Fact Check), and executes deterministic risk synthesis."
    ),
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handler for uniform error format
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred during processing. The incident has been logged.",
            "detail": str(exc) if settings.DEBUG else None,
        },
    )


# Mount Routers
app.include_router(system_router)
app.include_router(investigations_router, prefix=settings.API_V1_STR)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=settings.DEBUG)
