"""Environment configuration and runtime settings loader."""

import os
from dataclasses import dataclass
from typing import Final

DEFAULT_MAX_FILE_SIZE_BYTES: Final[int] = 1024 * 1024 * 1024  # 1 GB
DEFAULT_WORKERS: Final[int] = 4
DEFAULT_CHUNK_SIZE: Final[int] = 1000


@dataclass(frozen=True)
class Settings:
    """System-wide configuration settings with environment overrides."""

    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8000"))
    environment: str = os.getenv("ENVIRONMENT", "development")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./wireless_traffic.db")

    # E1 Specific Settings
    max_file_size_bytes: int = int(os.getenv("MAX_FILE_SIZE_BYTES", str(DEFAULT_MAX_FILE_SIZE_BYTES)))
    default_workers: int = int(os.getenv("DEFAULT_WORKERS", str(DEFAULT_WORKERS)))
    chunk_size: int = int(os.getenv("CHUNK_SIZE", str(DEFAULT_CHUNK_SIZE)))
    zero_copy_enabled: bool = os.getenv("ZERO_COPY_ENABLED", "true").lower() in ("true", "1", "yes")

    # E4 Alert Generation Settings
    max_alert_retries: int = int(os.getenv("MAX_ALERT_RETRIES", "3"))
    alert_retry_delay_seconds: float = float(os.getenv("ALERT_RETRY_DELAY_SECONDS", "0.1"))
    alert_dedup_cache_size: int = int(os.getenv("ALERT_DEDUP_CACHE_SIZE", "10000"))

    # Security
    secret_key: str = os.getenv("SECRET_KEY", "change_this_secret_key_in_production")
    algorithm: str = os.getenv("ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))


# Singleton configuration instance
settings = Settings()
