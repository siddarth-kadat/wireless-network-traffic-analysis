"""FastAPI Route Handler: Security Alerts Triage and Operations."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, select

from backend.src.database.connection import SessionLocal
from backend.src.database.models import Alert
from backend.src.engines.e3_log_alert_storage.alert_repository import AlertRepository

router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])


class AlertStatusUpdate(BaseModel):
    status: str


def _format_alert(a: Alert) -> Dict[str, Any]:
    details = a.alert_details
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except Exception:
            pass

    alert_type = "Wireless Threat"
    message = "Suspicious network pattern identified."
    if isinstance(details, dict):
        alert_type = (
            details.get("suspicious_activity")
            or details.get("threat_name")
            or details.get("rule_name")
            or alert_type
        )
        message = (
            details.get("summary_description")
            or details.get("description")
            or details.get("message")
            or message
        )

    return {
        "alert_id": str(a.alert_uuid),
        "internal_id": a.alert_id,
        "result_id": str(a.result_id),
        "alert_details": details,
        "alert_timestamp": a.alert_timestamp.isoformat() if a.alert_timestamp else "",
        "generated_at": a.alert_timestamp.isoformat() if a.alert_timestamp else "",
        "severity": a.severity,
        "alert_status": a.alert_status,
        "status": a.alert_status,
        "alert_type": alert_type,
        "message": message,
    }


@router.get("")
@router.get("/")
def get_alerts(
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve paginated security alerts with optional severity and status filters."""
    offset = (page - 1) * limit
    with SessionLocal() as session:
        query = select(Alert)

        if severity and severity.upper() != "ALL":
            query = query.where(Alert.severity == severity.upper())

        if status_filter and status_filter.upper() != "ALL":
            query = query.where(Alert.alert_status == status_filter.upper())

        if search:
            s = f"%{search}%"
            query = query.where(Alert.alert_details.ilike(s))

        count_stmt = select(func.count()).select_from(query.subquery())
        total = session.scalar(count_stmt) or 0

        stmt = query.order_by(Alert.alert_id.desc()).offset(offset).limit(limit)
        alerts = list(session.scalars(stmt).all())

        return {
            "total": total,
            "page": page,
            "limit": limit,
            "items": [_format_alert(a) for a in alerts],
        }


@router.get("/{alert_id}")
def get_alert_by_id(alert_id: str) -> Dict[str, Any]:
    """Retrieve details for a single security alert."""
    with SessionLocal() as session:
        alert = None
        try:
            a_uuid = uuid.UUID(alert_id)
            alert = session.scalars(
                select(Alert).where(Alert.alert_uuid == a_uuid)
            ).first()
        except (ValueError, TypeError):
            pass

        if not alert and alert_id.isdigit():
            alert = session.get(Alert, int(alert_id))

        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found.",
            )

        return _format_alert(alert)


@router.patch("/{alert_id}/status")
def update_alert_status(alert_id: str, update: AlertStatusUpdate) -> Dict[str, Any]:
    """Updates status for an alert (e.g. ACKNOWLEDGED or RESOLVED)."""
    with SessionLocal() as session:
        repo = AlertRepository(session)
        alert = None
        try:
            a_uuid = uuid.UUID(alert_id)
            alert = repo.get_by_uuid(a_uuid)
        except (ValueError, TypeError):
            pass

        if not alert and alert_id.isdigit():
            alert = repo.get_by_id(int(alert_id))

        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found.",
            )

        new_status = update.status.strip().upper()
        updated = repo.update_status(alert.alert_id, new_status)
        session.commit()
        return _format_alert(updated)
