"""Database engine configuration and session factory."""

import os
from pathlib import Path
from typing import Generator, Optional

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

# Resolve project root relative to connection.py location:
# backend/src/database/connection.py -> parents[3] is project root
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"

# Load project-root .env file before reading environment variables or initializing engine
load_dotenv(dotenv_path=ENV_FILE, override=False)


class DatabaseConnectionError(Exception):
    """Raised when database connection establishment or connectivity checks fail."""
    pass


class DatabaseConfigurationError(Exception):
    """Raised when required database configuration is missing or invalid."""
    pass


def get_database_url() -> str:
    """Build and return the PostgreSQL database URL using SQLAlchemy URL.create().

    Reads DATABASE_URL if explicitly set, normalizing dialect prefix to
    'postgresql+psycopg://' to ensure psycopg 3 is used.
    Otherwise constructs the URL from individual DB_* environment variables using
    SQLAlchemy's URL.create() so credentials and special characters are safely escaped.
    Does not log or expose credentials in plain text.
    """
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.strip():
        db_url_str = database_url.strip()
        if db_url_str.startswith("postgresql://"):
            db_url_str = db_url_str.replace("postgresql://", "postgresql+psycopg://", 1)
        elif db_url_str.startswith("postgres://"):
            db_url_str = db_url_str.replace("postgres://", "postgresql+psycopg://", 1)
        elif db_url_str.startswith("sqlite"):
            raise DatabaseConfigurationError(
                "SQLite is not supported. Please configure a PostgreSQL database URL using 'postgresql+psycopg://'."
            )
        return db_url_str

    db_user = os.getenv("DB_USER")
    db_name = os.getenv("DB_NAME")
    db_password = os.getenv("DB_PASSWORD")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port_str = os.getenv("DB_PORT", "5432")

    missing = []
    if not db_user:
        missing.append("DB_USER")
    if not db_name:
        missing.append("DB_NAME")
    if db_password is None:
        missing.append("DB_PASSWORD")

    if missing:
        raise DatabaseConfigurationError(
            f"Missing required database configuration: {', '.join(missing)} must be set, or provide 'DATABASE_URL'."
        )

    port: Optional[int] = None
    if db_port_str:
        try:
            port = int(db_port_str)
            if not (1 <= port <= 65535):
                raise ValueError()
        except ValueError as exc:
            raise DatabaseConfigurationError(
                f"Invalid DB_PORT '{db_port_str}': must be an integer between 1 and 65535."
            ) from exc

    url_object = URL.create(
        drivername="postgresql+psycopg",
        username=db_user,
        password=db_password if db_password else None,
        host=db_host,
        port=port,
        database=db_name,
    )
    return url_object.render_as_string(hide_password=False)


# Module-level engine and SessionLocal references
engine = None
SessionLocal = None


def init_engine(db_url: Optional[str] = None):
    """Initialize or re-initialize the SQLAlchemy engine and SessionLocal factory."""
    global engine, SessionLocal
    url = db_url or get_database_url()
    engine = create_engine(
        url,
        pool_size=int(os.getenv("DB_POOL_SIZE", "10")),
        max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "20")),
        pool_pre_ping=True,
        pool_recycle=int(os.getenv("DB_POOL_RECYCLE", "3600")),
    )
    SessionLocal = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    return engine


# Attempt eager initialization if environment configuration is present
try:
    init_engine()
except DatabaseConfigurationError:
    # Awaits explicit configuration or environment loading
    pass


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session scope for request lifecycles.

    Yields an active Session and ensures safe cleanup: rolls back uncommitted
    transactions on error and always closes the session in the finally block.
    """
    if SessionLocal is None:
        init_engine()

    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def check_db_connection() -> bool:
    """Validate database connectivity and raise informative errors on failure.

    Executes a simple query to verify network and credentials.
    Returns True if successful, or raises DatabaseConnectionError with context.
    Never exposes passwords or credential-bearing URLs in errors or logs.
    """
    if engine is None:
        init_engine()

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except OperationalError as exc:
        raise DatabaseConnectionError(
            f"Failed to connect to PostgreSQL database: {exc}"
        ) from exc
    except SQLAlchemyError as exc:
        raise DatabaseConnectionError(
            f"SQLAlchemy error during connectivity verification: {exc}"
        ) from exc
