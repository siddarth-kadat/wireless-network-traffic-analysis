"""FastAPI Application Main Entry Point for W-NTASSOC."""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import AsyncGenerator, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.src.common.logger import get_logger
from backend.src.database.initialization import init_database
from .administrator_routes import router as admin_router
from .alert_routes import router as alert_router
from .auth_routes import router as auth_router
from .detection_routes import router as detection_router
from .log_routes import router as log_router
from .user_routes import router as user_router

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager: initializes database and seed entities on startup."""
    logger.info("Initializing W-NTASSOC database and pre-seeding approved entities...")
    try:
        init_database()
        logger.info("Database initialization completed successfully.")
    except Exception as exc:
        logger.error("Failed to initialize database during startup: %s", exc, exc_info=True)
    yield
    logger.info("W-NTASSOC API shutting down.")


app = FastAPI(
    title="Wireless Network Traffic Analysis and Alerting System (W-NTASSOC)",
    description="Cybersecurity SOC Monitoring and Threat Intelligence REST API",
    version="2.4.1",
    lifespan=lifespan,
)

# Configure Cross-Origin Resource Sharing (CORS) for React Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register route controllers
app.include_router(auth_router)
app.include_router(log_router)
app.include_router(detection_router)
app.include_router(alert_router)
app.include_router(user_router)
app.include_router(admin_router)


@app.get("/", tags=["Health & Status"])
def root() -> Dict[str, str]:
    """Root status ping."""
    return {
        "system": "W-NTASSOC Cyber SOC",
        "version": "2.4.1",
        "status": "ONLINE",
        "documentation": "/docs",
    }


@app.get("/api/health", tags=["Health & Status"])
def health_check() -> Dict[str, str]:
    """System and backend health check endpoint."""
    return {
        "status": "UP",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "backend": "FastAPI",
    }
