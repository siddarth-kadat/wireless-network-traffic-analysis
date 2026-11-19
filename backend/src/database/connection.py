"""Database engine configuration and session factory."""

import os
from pathlib import Path
from typing import Generator, Optional

from dotenv import load_dotenv
from sqlalchemy import BigInteger, create_engine, event, text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.engine import URL
from sqlalchemy.exc import OperationalError, SQLAlchemyError
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

# ---------------------------------------------------------------------------
# Cross-dialect schema compatibility compiler hooks
# ---------------------------------------------------------------------------
@compiles(PG_UUID, "sqlite")
def _compile_pg_uuid_sqlite(type_, compiler, **kw):
    return "CHAR(36)"


@compiles(BigInteger, "sqlite")
def _compile_bigint_sqlite(type_, compiler, **kw):
    return "INTEGER"


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
    """Build and return database URL (SQLite default or PostgreSQL when configured)."""
    database_url = os.getenv("DATABASE_URL")
    if database_url and database_url.strip():
        db_url_str = database_url.strip()
        if db_url_str.startswith("postgresql://"):
            return db_url_str.replace("postgresql://", "postgresql+psycopg://", 1)
        elif db_url_str.startswith("postgres://"):
            return db_url_str.replace("postgres://", "postgresql+psycopg://", 1)
        return db_url_str

    db_user = os.getenv("DB_USER")
    db_name = os.getenv("DB_NAME")
    db_password = os.getenv("DB_PASSWORD")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port_str = os.getenv("DB_PORT", "5432")

    # If explicit postgres credentials are provided in env, construct PostgreSQL URL
    if db_user and db_name:
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

    # Default to local SQLite database (per approved architecture: E3 -> SQLite Database)
    default_db_path = PROJECT_ROOT / "data" / "w_ntassoc.db"
    default_db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{default_db_path.as_posix()}"


# Module-level engine and SessionLocal references
engine = None
SessionLocal = None


def init_engine(db_url: Optional[str] = None):
    """Initialize or re-initialize the SQLAlchemy engine and SessionLocal factory."""
    global engine, SessionLocal
    url = db_url or get_database_url()

    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()
    else:
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


# Attempt eager initialization
try:
    init_engine()
except Exception:
    pass


def get_db() -> Generator[Session, None, None]:
    """Provide a transactional database session scope for request lifecycles."""
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
    """Validate database connectivity."""
    if engine is None:
        init_engine()

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except OperationalError as exc:
        raise DatabaseConnectionError(
            f"Failed to connect to database: {exc}"
        ) from exc
    except SQLAlchemyError as exc:
        raise DatabaseConnectionError(
            f"SQLAlchemy error during connectivity verification: {exc}"
        ) from exc
