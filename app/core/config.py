"""TrustLens AI - Core Configuration

Central configuration module managing environment variables, API endpoints,
model parameters, security limits, and service credentials.
"""

from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "TrustLens AI Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "production"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "trustlens-insecure-secret-key-change-in-production"

    # Meta Model API Settings (Mandatory)
    MODEL_API_KEY: str = Field(default="", description="Meta Model API Bearer Token")
    META_BASE_URL: str = Field(default="https://api.meta.ai/v1", description="Base URL for Meta Model API")
    META_MODEL_ID: str = Field(default="muse-spark-1.3", description="Multimodal reasoning model identifier")
    META_VOICE_MODEL_ID: str = Field(default="muse-voice-transcribe-1.0", description="Voice transcription model identifier")
    META_TIMEOUT_SECONDS: int = Field(default=60, description="Timeout for Meta API requests in seconds")
    META_MAX_RETRIES: int = Field(default=3, description="Maximum retries for transient Meta API errors")

    # Threat Intelligence Providers
    VIRUSTOTAL_API_KEY: Optional[str] = Field(default=None, description="VirusTotal v3 API Key")
    PHISHTANK_API_KEY: Optional[str] = Field(default=None, description="PhishTank API Key (optional)")
    URLHAUS_API_KEY: Optional[str] = Field(default=None, description="URLhaus Auth-Key (optional)")
    GOOGLE_FACTCHECK_API_KEY: Optional[str] = Field(default=None, description="Google Fact Check Tools API Key")

    # Database
    DATABASE_URL: str = Field(
        default="sqlite+aiosqlite:///./trustlens.db",
        description="Async database connection string. Use postgresql+asyncpg://user:pass@host/db in production.",
    )
    DB_ECHO: bool = False

    # Redis / Task Queue (Optional)
    REDIS_URL: Optional[str] = Field(default=None, description="Redis URL for distributed caching/queues")

    # Security & URL Inspection
    SAFE_URL_MAX_REDIRECTS: int = 5
    SAFE_URL_TIMEOUT_SECONDS: int = 8
    SAFE_URL_MAX_CONTENT_BYTES: int = 2 * 1024 * 1024  # 2MB max download preview
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024     # 25MB max file upload
    ALLOWED_IMAGE_TYPES: List[str] = [
        "image/jpeg",
        "image/png",
        "image/webp",
        "image/gif",
        "image/bmp",
    ]
    ALLOWED_AUDIO_TYPES: List[str] = [
        "audio/mpeg",
        "audio/wav",
        "audio/ogg",
        "audio/mp4",
        "audio/x-m4a",
        "audio/webm",
        "audio/aac",
    ]

    # Data Retention & Privacy
    RETENTION_DAYS: int = 30
    ENABLE_AUDIT_LOGGING: bool = True
    REDACT_PII_IN_LOGS: bool = True

    # CORS
    BACKEND_CORS_ORIGINS: List[str] = ["*"]


settings = Settings()
