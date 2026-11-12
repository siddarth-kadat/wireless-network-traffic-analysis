"""Alembic environment configuration."""

from logging.config import fileConfig
import os
import sys

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure project root and backend are on sys.path
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
project_root = os.path.abspath(os.path.join(backend_dir, ".."))

if project_root not in sys.path:
    sys.path.insert(0, project_root)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Import Base and models to ensure all 7 entities register in Base.metadata
from backend.src.database.base import Base
import backend.src.database.models  # noqa: F401
from backend.src.database.connection import get_database_url

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Target metadata for autogenerate support
target_metadata = Base.metadata


def get_offline_url() -> str:
    """Retrieve database URL for offline migration generation.

    Attempts to use the real configured URL. If configuration is unavailable,
    falls back to a placeholder PostgreSQL URL solely for offline SQL script generation.
    Never establishes a database connection.
    """
    try:
        return get_database_url()
    except Exception:
        # Fall back to alembic.ini value if explicitly configured
        ini_url = config.get_main_option("sqlalchemy.url")
        if ini_url and ini_url.strip():
            return ini_url.strip()
        # Placeholder dialect URL solely for offline SQL emission when credentials are unset
        return "postgresql+psycopg://postgres:placeholder@localhost:5432/wireless_traffic_db"


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    Configures the context with just a URL and not an Engine.
    Calls to context.execute() emit the given string to the script output.
    """
    url = get_offline_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Creates an Engine and associates a connection with the context.
    Uses psycopg 3 driver via postgresql+psycopg dialect.
    Strictly obtains the database URL directly through get_database_url()
    and fails fast if configuration is missing, preventing placeholder fallback leakage.
    """
    url = get_database_url()
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
