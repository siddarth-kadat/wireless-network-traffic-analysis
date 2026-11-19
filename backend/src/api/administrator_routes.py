"""FastAPI Route Handler: Administrator Telemetry and System Health."""

from __future__ import annotations

import os
from typing import Any, Dict
from fastapi import APIRouter
from sqlalchemy import func, select

from backend.src.database.connection import SessionLocal
from backend.src.database.models import (
    Alert,
    Detection_Result,
    Detection_Rule,
    Log_Batch,
    Processing_Error,
    Traffic_Log,
    User,
)

router = APIRouter(prefix="/api/admin", tags=["Administrator & System Health"])


@router.get("/system/status")
@router.get("/metrics")
def get_system_metrics() -> Dict[str, Any]:
    """Provides high-level system, engine, and database operational metrics."""
    with SessionLocal() as session:
        counts = {
            "users": session.scalar(select(func.count(User.user_id))) or 0,
            "batches": session.scalar(select(func.count(Log_Batch.batch_id))) or 0,
            "traffic_logs": session.scalar(select(func.count(Traffic_Log.log_id))) or 0,
            "rules": session.scalar(select(func.count(Detection_Rule.rule_id))) or 0,
            "detection_results": session.scalar(select(func.count(Detection_Result.result_id))) or 0,
            "alerts": session.scalar(select(func.count(Alert.alert_id))) or 0,
            "processing_errors": session.scalar(select(func.count(Processing_Error.error_id))) or 0,
        }

    return {
        "system": "W-NTASSOC Cyber SOC",
        "status": "OPERATIONAL",
        "database_type": "SQLite" if "sqlite" in os.getenv("DATABASE_URL", "sqlite") else "PostgreSQL",
        "engines": {
            "e1_log_processing": "ONLINE",
            "e2_detection": "ONLINE",
            "e3_storage": "ONLINE",
            "e4_alert_generation": "ONLINE",
        },
        "entity_counts": counts,
    }
