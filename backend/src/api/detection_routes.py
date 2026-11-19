"""FastAPI Route Handler: Detection Results and Rules."""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional, Union

from fastapi import APIRouter, HTTPException, Query, status
from sqlalchemy import func, select

from backend.src.database.connection import SessionLocal
from backend.src.database.models import Detection_Result, Detection_Rule
from backend.src.engines.e3_log_alert_storage.rule_repository import RuleRepository

router = APIRouter(prefix="/api/detection", tags=["Detection Rules & Results"])


def _format_rule(r: Detection_Rule) -> Dict[str, Any]:
    return {
        "rule_id": str(r.rule_id),
        "rule_name": r.rule_name,
        "suspicious_activity": r.suspicious_activity,
        "protocol": r.protocol,
        "detection_condition": r.detection_condition,
        "severity": r.severity,
        "threshold_value": r.threshold_value,
        "time_window_seconds": r.time_window_seconds,
        "is_enabled": r.is_enabled,
        "is_active": r.is_enabled,
        "description": r.suspicious_activity,
    }


def _format_result(res: Detection_Result, rule_name: str = "") -> Dict[str, Any]:
    evidence = res.detection_evidence
    if isinstance(evidence, str):
        try:
            evidence = json.loads(evidence)
        except Exception:
            pass

    return {
        "result_id": str(res.result_uuid),
        "internal_id": res.result_id,
        "log_id": str(res.log_id),
        "rule_id": str(res.rule_id),
        "rule_name": rule_name,
        "rule_match_status": res.rule_match_status,
        "is_suspicious": res.rule_match_status,
        "detection_time": res.detection_time.isoformat() if res.detection_time else "",
        "detection_timestamp": res.detection_time.isoformat() if res.detection_time else "",
        "observed_value": res.observed_value,
        "threshold_value": res.threshold_value,
        "detection_evidence": evidence,
        "evidence_data": evidence,
    }


# ==============================================================================
# Detection Rules
# ==============================================================================

@router.get("/rules")
def get_detection_rules() -> List[Dict[str, Any]]:
    """Retrieve all detection rules with their current enablement status."""
    with SessionLocal() as session:
        repo = RuleRepository(session)
        rules = repo.list_all(limit=500)
        return [_format_rule(r) for r in rules]


@router.post("/rules/{rule_id}/toggle")
@router.patch("/rules/{rule_id}/toggle")
def toggle_detection_rule(rule_id: str) -> Dict[str, Any]:
    """Toggle a detection rule's enabled/active state."""
    with SessionLocal() as session:
        repo = RuleRepository(session)
        target_rule = None
        if rule_id.isdigit():
            target_rule = repo.get_by_id(int(rule_id))
        if not target_rule:
            target_rule = repo.get_by_name(rule_id)

        if not target_rule:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection rule '{rule_id}' not found.",
            )

        new_state = not target_rule.is_enabled
        updated = repo.set_enabled(target_rule.rule_id, new_state)
        session.commit()
        return _format_rule(updated)


# ==============================================================================
# Detection Results
# ==============================================================================

@router.get("/results")
def get_detection_results(
    matchStatus: Optional[Union[str, bool]] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """Retrieve paginated detection results with optional matching filter."""
    offset = (page - 1) * limit
    with SessionLocal() as session:
        stmt = select(Detection_Result, Detection_Rule.rule_name).outerjoin(
            Detection_Rule, Detection_Result.rule_id == Detection_Rule.rule_id
        )

        if matchStatus is not None and matchStatus != "":
            is_matched = str(matchStatus).lower() in ("true", "1")
            stmt = stmt.where(Detection_Result.rule_match_status == is_matched)

        if search:
            s = f"%{search}%"
            stmt = stmt.where(Detection_Rule.rule_name.ilike(s))

        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = session.scalar(count_stmt) or 0

        stmt = stmt.order_by(Detection_Result.result_id.desc()).offset(offset).limit(limit)
        results = session.execute(stmt).all()

        items = [_format_result(row[0], row[1] or "") for row in results]
        return {
            "total": total,
            "page": page,
            "limit": limit,
            "items": items,
        }


@router.get("/results/{result_id}")
def get_detection_result_by_id(result_id: str) -> Dict[str, Any]:
    """Retrieve details for a single detection result by UUID or ID."""
    with SessionLocal() as session:
        res = None
        rule_name = ""
        try:
            r_uuid = uuid.UUID(result_id)
            row = session.execute(
                select(Detection_Result, Detection_Rule.rule_name)
                .outerjoin(Detection_Rule, Detection_Result.rule_id == Detection_Rule.rule_id)
                .where(Detection_Result.result_uuid == r_uuid)
            ).first()
            if row:
                res, rule_name = row[0], row[1]
        except (ValueError, TypeError):
            pass

        if not res and result_id.isdigit():
            row = session.execute(
                select(Detection_Result, Detection_Rule.rule_name)
                .outerjoin(Detection_Rule, Detection_Result.rule_id == Detection_Rule.rule_id)
                .where(Detection_Result.result_id == int(result_id))
            ).first()
            if row:
                res, rule_name = row[0], row[1]

        if not res:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Detection result '{result_id}' not found.",
            )

        return _format_result(res, rule_name or "")
