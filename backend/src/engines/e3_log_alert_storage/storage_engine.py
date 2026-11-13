"""E3: Primary database gateway — Log and Alert Storage Engine.

All persistent operations for E1, E2, and E4 payloads pass through this module.
It owns transaction boundaries: each public method opens, commits, or rolls back
its own unit of work using the SessionLocal factory from the database connection module.

Design principles
-----------------
- E3 never modifies E1, E2, or E4 engine code.
- E3 resolves external engine UUIDs to internal integer/BigInteger PKs.
- Serialization of dict values into Text columns happens here, not in repositories.
- ISO timestamp strings are parsed to timezone-aware datetime objects here.
- Duplicate UUIDs are detected and handled without silent data loss.
- Failed individual records are logged; they do not abort the whole batch.
"""

from __future__ import annotations

import json
import uuid as _uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Generator, List, Optional

from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session

from backend.src.database.connection import SessionLocal, init_engine
from backend.src.common.logger import get_logger
from .alert_repository import AlertRepository
from .batch_repository import BatchRepository
from .error_repository import ErrorRepository
from .log_repository import LogRepository
from .result_repository import ResultRepository
from .rule_repository import RuleRepository
from .user_repository import UserRepository

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_datetime(value: Optional[str]) -> datetime:
    """Parse an ISO 8601 timestamp string into a timezone-aware datetime.

    Falls back to UTC now if the value is None or unparseable.

    Args:
        value: ISO 8601 string, e.g. '2026-11-12T17:00:00+00:00' or '...Z'.

    Returns:
        Timezone-aware datetime in UTC.
    """
    if not value:
        return datetime.now(timezone.utc)
    # Replace trailing Z with +00:00 for fromisoformat compatibility (Python < 3.11)
    normalized = value.strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        logger.warning("_parse_datetime: could not parse '%s'; using UTC now.", value)
        return datetime.now(timezone.utc)


def _serialize(value: Any) -> Optional[str]:
    """Serialize a dict or other value to a JSON string for Text columns.

    Returns the value unchanged if it is already a string or None.

    Args:
        value: Arbitrary value (dict, str, None, …).

    Returns:
        JSON string, original string, or None.
    """
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, default=str)
    except (TypeError, ValueError):
        return str(value)


def _parse_uuid(value: Optional[str]) -> Optional[_uuid.UUID]:
    """Parse a UUID string into a uuid.UUID object.

    Args:
        value: UUID string or None.

    Returns:
        uuid.UUID object, or None if value is None or invalid.
    """
    if not value:
        return None
    try:
        return _uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Session context manager
# ---------------------------------------------------------------------------

@contextmanager
def _session_scope() -> Generator[Session, None, None]:
    """Provide a transactional Session scope.

    Commits on clean exit; rolls back and re-raises on exception.
    Always closes the session in the finally block.
    """
    if SessionLocal is None:
        init_engine()
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# ---------------------------------------------------------------------------
# StorageEngine
# ---------------------------------------------------------------------------

class StorageEngine:
    """E3 storage engine — the single persistence gateway for all engines.

    Public methods are transactional: each creates its own Session, commits
    on success, or rolls back on failure.  Repositories are instantiated per
    call and share the same Session within a transaction.

    Usage::

        engine = StorageEngine()
        result = engine.store_e1_batch(storage_output, user_id=1)
    """

    # ------------------------------------------------------------------
    # E1: batch + traffic logs + errors
    # ------------------------------------------------------------------

    def store_e1_batch(
        self,
        storage_output: Dict[str, Any],
        user_id: int,
    ) -> Dict[str, Any]:
        """Persist the complete E1StorageOutput for a processed PCAP file.

        Stores batch metadata, traffic logs, and processing errors atomically.
        Returns a summary dict with internal IDs and counts.

        Args:
            storage_output: E1StorageOutput.batch_metadata / .traffic_logs / .errors
                            as produced by E1ProcessingPipeline.process_file().
                            Accepted as a dict (call storage_output.__dict__ or
                            pass each field directly).
            user_id: Internal integer PK of the submitting user.

        Returns:
            Dict with keys:
                batch_id      : int    — internal batch PK
                batch_uuid    : str    — E1 UUID
                logs_stored   : int    — number of traffic_log rows persisted
                errors_stored : int    — number of processing_error rows persisted
                logs_skipped  : int    — duplicates skipped
                errors_skipped: int    — duplicates skipped

        Raises:
            ValueError: If batch_uuid is missing or invalid.
            SQLAlchemyError: On unrecoverable database errors.
        """
        # Accept E1StorageOutput object or plain dict
        if hasattr(storage_output, "__dict__") and not isinstance(storage_output, dict):
            meta = storage_output.batch_metadata
            raw_logs = storage_output.traffic_logs
            raw_errors = storage_output.errors
        else:
            meta = storage_output.get("batch_metadata", storage_output)
            raw_logs = storage_output.get("traffic_logs", [])
            raw_errors = storage_output.get("errors", [])

        # Parse / validate batch UUID
        batch_uuid_str = str(meta.get("batch_id", ""))
        batch_uuid = _parse_uuid(batch_uuid_str)
        if batch_uuid is None:
            raise ValueError(
                f"store_e1_batch: batch_uuid is missing or invalid: '{batch_uuid_str}'"
            )

        with _session_scope() as session:
            batch_repo = BatchRepository(session)
            log_repo = LogRepository(session)
            error_repo = ErrorRepository(session)

            # ---- Batch ------------------------------------------------
            if batch_repo.exists_by_uuid(batch_uuid):
                logger.warning(
                    "store_e1_batch: batch_uuid=%s already exists; skipping batch creation.",
                    batch_uuid,
                )
                batch = batch_repo.get_by_uuid(batch_uuid)
            else:
                submitted_at = _parse_datetime(meta.get("submitted_at"))
                batch = batch_repo.create(
                    batch_uuid=batch_uuid,
                    user_id=user_id,
                    file_name=str(meta.get("file_name", "")),
                    file_format=str(meta.get("file_format", "")),
                    submitted_at=submitted_at,
                    processing_status=str(meta.get("processing_status", "UNKNOWN")),
                    total_records=int(meta.get("total_records", 0)),
                    processed_records=int(meta.get("processed_records", 0)),
                    failed_records=int(meta.get("failed_records", 0)),
                )

            batch_id: int = batch.batch_id

            # ---- Traffic logs ----------------------------------------
            logs_stored = 0
            logs_skipped = 0
            for raw in raw_logs:
                log_uuid = _parse_uuid(raw.get("log_id"))
                if log_uuid is None:
                    logger.warning(
                        "store_e1_batch: traffic_log missing valid log_id UUID; skipping."
                    )
                    logs_skipped += 1
                    continue
                if log_repo.exists_by_uuid(log_uuid):
                    logger.debug(
                        "store_e1_batch: log_uuid=%s already exists; skipping.", log_uuid
                    )
                    logs_skipped += 1
                    continue
                try:
                    log_repo.create(
                        log_uuid=log_uuid,
                        batch_id=batch_id,
                        timestamp=_parse_datetime(raw.get("timestamp")),
                        source_address=str(raw.get("source_address") or ""),
                        destination_address=str(raw.get("destination_address") or ""),
                        protocol=str(raw.get("protocol", "UNKNOWN")),
                        source_mac=raw.get("source_mac"),
                        destination_mac=raw.get("destination_mac"),
                        log_details=_serialize(raw.get("log_details")),
                    )
                    logs_stored += 1
                except IntegrityError:
                    logger.warning(
                        "store_e1_batch: IntegrityError for log_uuid=%s; skipping.", log_uuid
                    )
                    logs_skipped += 1
                except Exception as exc:
                    logger.error(
                        "store_e1_batch: unexpected error for log_uuid=%s: %s", log_uuid, exc
                    )
                    logs_skipped += 1

            # ---- Processing errors -----------------------------------
            errors_stored = 0
            errors_skipped = 0
            for raw in raw_errors:
                error_uuid = _parse_uuid(raw.get("error_id"))
                if error_uuid is None:
                    logger.warning(
                        "store_e1_batch: processing_error missing valid error_id UUID; skipping."
                    )
                    errors_skipped += 1
                    continue
                if error_repo.exists_by_uuid(error_uuid):
                    logger.debug(
                        "store_e1_batch: error_uuid=%s already exists; skipping.", error_uuid
                    )
                    errors_skipped += 1
                    continue

                # Resolve optional log_id UUID to internal int FK
                raw_log_id: Optional[int] = None
                raw_log_uuid_str = raw.get("log_id")
                if raw_log_uuid_str:
                    log_uuid_obj = _parse_uuid(str(raw_log_uuid_str))
                    if log_uuid_obj:
                        raw_log_id = log_repo.get_internal_id_by_uuid(log_uuid_obj)

                try:
                    error_repo.create(
                        error_uuid=error_uuid,
                        batch_id=batch_id,
                        error_type=str(raw.get("error_type", "UnknownError")),
                        error_message=str(raw.get("error_message", "")),
                        error_timestamp=_parse_datetime(raw.get("error_timestamp")),
                        log_id=raw_log_id,
                    )
                    errors_stored += 1
                except IntegrityError:
                    logger.warning(
                        "store_e1_batch: IntegrityError for error_uuid=%s; skipping.", error_uuid
                    )
                    errors_skipped += 1
                except Exception as exc:
                    logger.error(
                        "store_e1_batch: unexpected error for error_uuid=%s: %s", error_uuid, exc
                    )
                    errors_skipped += 1

            logger.info(
                "store_e1_batch: batch_uuid=%s, batch_id=%d, "
                "logs_stored=%d, logs_skipped=%d, errors_stored=%d, errors_skipped=%d",
                batch_uuid,
                batch_id,
                logs_stored,
                logs_skipped,
                errors_stored,
                errors_skipped,
            )

            return {
                "batch_id": batch_id,
                "batch_uuid": str(batch_uuid),
                "logs_stored": logs_stored,
                "errors_stored": errors_stored,
                "logs_skipped": logs_skipped,
                "errors_skipped": errors_skipped,
            }

    # ------------------------------------------------------------------
    # E2: detection rules retrieval
    # ------------------------------------------------------------------

    def get_enabled_rules(self) -> List[Dict[str, Any]]:
        """Retrieve all enabled Detection_Rules for E2.

        Returns:
            List of dicts with Detection_Rule fields:
                rule_id, rule_name, suspicious_activity, protocol,
                detection_condition, threshold_value, time_window_seconds, severity.
        """
        with _session_scope() as session:
            repo = RuleRepository(session)
            rules = repo.get_enabled_rules()
            return [
                {
                    "rule_id": r.rule_id,
                    "rule_name": r.rule_name,
                    "suspicious_activity": r.suspicious_activity,
                    "protocol": r.protocol,
                    "detection_condition": r.detection_condition,
                    "threshold_value": r.threshold_value,
                    "time_window_seconds": r.time_window_seconds,
                    "severity": r.severity,
                }
                for r in rules
            ]

    # ------------------------------------------------------------------
    # E2: store detection result
    # ------------------------------------------------------------------

    def store_detection_result(
        self,
        result_uuid: str,
        log_uuid: str,
        rule_id: int,
        rule_match_status: bool,
        detection_time: str,
        observed_value: Optional[float] = None,
        threshold_value: Optional[float] = None,
        detection_evidence: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Persist a single Detection_Result supplied by E2.

        E3 input contract (E2 not yet implemented — defined here for integration):

        Required fields
        ---------------
        result_uuid       : str   — UUID4 generated by E2
        log_uuid          : str   — E1-generated log UUID (resolved to log_id)
        rule_id           : int   — Detection_Rule.rule_id integer PK
        rule_match_status : bool  — True = matched / suspicious
        detection_time    : str   — ISO 8601 UTC timestamp

        Optional fields
        ---------------
        observed_value    : float | None
        threshold_value   : float | None
        detection_evidence: dict | str | None  — serialized to JSON Text

        Args:
            result_uuid: E2-generated UUID string.
            log_uuid: E1 log UUID string; resolved to internal log_id.
            rule_id: Integer FK matching detection_rules.rule_id.
            rule_match_status: True if rule matched.
            detection_time: ISO 8601 timestamp string.
            observed_value: Optional observed metric.
            threshold_value: Optional threshold.
            detection_evidence: Optional evidence dict or string.

        Returns:
            Dict with keys:
                result_id   : int  — internal BigInteger PK
                result_uuid : str  — E2 UUID
                skipped     : bool — True if UUID was a duplicate

        Raises:
            ValueError: If result_uuid or log_uuid is missing/invalid, or
                        if the referenced log_uuid does not exist in the database.
        """
        r_uuid = _parse_uuid(result_uuid)
        if r_uuid is None:
            raise ValueError(f"store_detection_result: invalid result_uuid='{result_uuid}'")

        l_uuid = _parse_uuid(log_uuid)
        if l_uuid is None:
            raise ValueError(f"store_detection_result: invalid log_uuid='{log_uuid}'")

        with _session_scope() as session:
            result_repo = ResultRepository(session)
            log_repo = LogRepository(session)

            if result_repo.exists_by_uuid(r_uuid):
                logger.warning(
                    "store_detection_result: result_uuid=%s already exists; skipping.", r_uuid
                )
                existing = result_repo.get_by_uuid(r_uuid)
                return {
                    "result_id": existing.result_id,
                    "result_uuid": str(r_uuid),
                    "skipped": True,
                }

            log_id = log_repo.get_internal_id_by_uuid(l_uuid)
            if log_id is None:
                raise ValueError(
                    f"store_detection_result: log_uuid='{log_uuid}' not found in database."
                )

            result = result_repo.create(
                result_uuid=r_uuid,
                log_id=log_id,
                rule_id=rule_id,
                rule_match_status=rule_match_status,
                detection_time=_parse_datetime(detection_time),
                observed_value=observed_value,
                threshold_value=threshold_value,
                detection_evidence=_serialize(detection_evidence),
            )

            logger.info(
                "store_detection_result: result_uuid=%s, result_id=%d, matched=%s",
                r_uuid,
                result.result_id,
                rule_match_status,
            )
            return {
                "result_id": result.result_id,
                "result_uuid": str(r_uuid),
                "skipped": False,
            }

    # ------------------------------------------------------------------
    # E4: store alert
    # ------------------------------------------------------------------

    def store_alert(self, alert_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Persist an E4-generated alert payload.

        This method is the callable passed to E4's AlertDispatcher.set_storage_sink().
        E4 calls it with AlertPayload.to_dict().

        Expected keys in alert_dict (from AlertPayload.to_dict()):
            alert_id        : str  — E4-generated UUID (maps to alert_uuid)
            result_id       : str  — E2 result UUID (resolved to internal result_id)
            alert_details   : dict — serialized to JSON Text
            alert_timestamp : str  — ISO 8601 UTC timestamp
            severity        : str  — severity level string
            alert_status    : str  — initial status (e.g. 'NEW')

        Args:
            alert_dict: Alert payload dictionary from AlertPayload.to_dict().

        Returns:
            Dict with keys:
                alert_id    : int  — internal integer PK
                alert_uuid  : str  — E4 UUID
                skipped     : bool — True if UUID was a duplicate

        Raises:
            ValueError: If alert_uuid, result_uuid, or referenced result is invalid.
        """
        alert_uuid_str = str(alert_dict.get("alert_id", ""))
        a_uuid = _parse_uuid(alert_uuid_str)
        if a_uuid is None:
            raise ValueError(f"store_alert: invalid alert_id='{alert_uuid_str}'")

        result_uuid_str = str(alert_dict.get("result_id", ""))
        r_uuid = _parse_uuid(result_uuid_str)
        if r_uuid is None:
            raise ValueError(f"store_alert: invalid result_id='{result_uuid_str}'")

        with _session_scope() as session:
            alert_repo = AlertRepository(session)
            result_repo = ResultRepository(session)

            if alert_repo.exists_by_uuid(a_uuid):
                logger.warning(
                    "store_alert: alert_uuid=%s already exists; skipping.", a_uuid
                )
                existing = alert_repo.get_by_uuid(a_uuid)
                return {
                    "alert_id": existing.alert_id,
                    "alert_uuid": str(a_uuid),
                    "skipped": True,
                }

            # Resolve E2 result UUID → internal result_id integer
            result_id = result_repo.get_internal_id_by_uuid(r_uuid)
            if result_id is None:
                raise ValueError(
                    f"store_alert: result_uuid='{result_uuid_str}' not found in database."
                )

            # Enforce 1-to-0-or-1 cardinality
            if alert_repo.exists_for_result(result_id):
                logger.warning(
                    "store_alert: alert already exists for result_id=%d; skipping.", result_id
                )
                existing = alert_repo.get_by_result_id(result_id)
                return {
                    "alert_id": existing.alert_id,
                    "alert_uuid": str(a_uuid),
                    "skipped": True,
                }

            alert = alert_repo.create(
                alert_uuid=a_uuid,
                result_id=result_id,
                alert_details=_serialize(alert_dict.get("alert_details")),
                alert_timestamp=_parse_datetime(alert_dict.get("alert_timestamp")),
                severity=str(alert_dict.get("severity", "UNKNOWN")),
                alert_status=str(alert_dict.get("alert_status", "NEW")),
            )

            logger.info(
                "store_alert: alert_uuid=%s, alert_id=%d, result_id=%d, severity=%s",
                a_uuid,
                alert.alert_id,
                result_id,
                alert.severity,
            )
            return {
                "alert_id": alert.alert_id,
                "alert_uuid": str(a_uuid),
                "skipped": False,
            }

    # ------------------------------------------------------------------
    # Retrieval helpers
    # ------------------------------------------------------------------

    def get_traffic_logs(
        self,
        batch_uuid: str,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return paginated traffic logs for a given batch UUID.

        Args:
            batch_uuid: E1 batch UUID string.
            offset: Records to skip.
            limit: Maximum records to return.

        Returns:
            List of dicts with Traffic_Log fields.

        Raises:
            ValueError: If batch_uuid is invalid or not found.
        """
        b_uuid = _parse_uuid(batch_uuid)
        if b_uuid is None:
            raise ValueError(f"get_traffic_logs: invalid batch_uuid='{batch_uuid}'")

        with _session_scope() as session:
            batch_repo = BatchRepository(session)
            log_repo = LogRepository(session)

            batch_id = batch_repo.get_internal_id_by_uuid(b_uuid)
            if batch_id is None:
                raise ValueError(f"get_traffic_logs: batch_uuid='{batch_uuid}' not found.")

            logs = log_repo.list_by_batch(batch_id, offset=offset, limit=limit)
            return [
                {
                    "log_id": l.log_id,
                    "log_uuid": str(l.log_uuid),
                    "batch_id": l.batch_id,
                    "timestamp": l.timestamp.isoformat(),
                    "source_address": l.source_address,
                    "destination_address": l.destination_address,
                    "source_mac": l.source_mac,
                    "destination_mac": l.destination_mac,
                    "protocol": l.protocol,
                    "log_details": l.log_details,
                }
                for l in logs
            ]

    def get_detection_results(
        self,
        log_uuid: str,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return paginated detection results for a given log UUID.

        Args:
            log_uuid: E1 log UUID string.
            offset: Records to skip.
            limit: Maximum records to return.

        Returns:
            List of dicts with Detection_Result fields.

        Raises:
            ValueError: If log_uuid is invalid or not found.
        """
        l_uuid = _parse_uuid(log_uuid)
        if l_uuid is None:
            raise ValueError(f"get_detection_results: invalid log_uuid='{log_uuid}'")

        with _session_scope() as session:
            log_repo = LogRepository(session)
            result_repo = ResultRepository(session)

            log_id = log_repo.get_internal_id_by_uuid(l_uuid)
            if log_id is None:
                raise ValueError(f"get_detection_results: log_uuid='{log_uuid}' not found.")

            results = result_repo.list_by_log(log_id, offset=offset, limit=limit)
            return [
                {
                    "result_id": r.result_id,
                    "result_uuid": str(r.result_uuid),
                    "log_id": r.log_id,
                    "rule_id": r.rule_id,
                    "rule_match_status": r.rule_match_status,
                    "observed_value": r.observed_value,
                    "threshold_value": r.threshold_value,
                    "detection_evidence": r.detection_evidence,
                    "detection_time": r.detection_time.isoformat(),
                }
                for r in results
            ]

    def get_alerts(
        self,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return paginated alerts, newest first.

        Args:
            offset: Records to skip.
            limit: Maximum records to return.

        Returns:
            List of dicts with Alert fields.
        """
        with _session_scope() as session:
            repo = AlertRepository(session)
            alerts = repo.list_all(offset=offset, limit=limit)
            return [
                {
                    "alert_id": a.alert_id,
                    "alert_uuid": str(a.alert_uuid),
                    "result_id": a.result_id,
                    "alert_details": a.alert_details,
                    "alert_timestamp": a.alert_timestamp.isoformat(),
                    "severity": a.severity,
                    "alert_status": a.alert_status,
                }
                for a in alerts
            ]

    def get_processing_errors(
        self,
        batch_uuid: str,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Return paginated processing errors for a batch UUID.

        Args:
            batch_uuid: E1 batch UUID string.
            offset: Records to skip.
            limit: Maximum records to return.

        Returns:
            List of dicts with Processing_Error fields.

        Raises:
            ValueError: If batch_uuid is invalid or not found.
        """
        b_uuid = _parse_uuid(batch_uuid)
        if b_uuid is None:
            raise ValueError(f"get_processing_errors: invalid batch_uuid='{batch_uuid}'")

        with _session_scope() as session:
            batch_repo = BatchRepository(session)
            error_repo = ErrorRepository(session)

            batch_id = batch_repo.get_internal_id_by_uuid(b_uuid)
            if batch_id is None:
                raise ValueError(f"get_processing_errors: batch_uuid='{batch_uuid}' not found.")

            errors = error_repo.list_by_batch(batch_id, offset=offset, limit=limit)
            return [
                {
                    "error_id": e.error_id,
                    "error_uuid": str(e.error_uuid),
                    "batch_id": e.batch_id,
                    "log_id": e.log_id,
                    "error_type": e.error_type,
                    "error_message": e.error_message,
                    "error_timestamp": e.error_timestamp.isoformat(),
                }
                for e in errors
            ]

    # ------------------------------------------------------------------
    # E4 sink adapter
    # ------------------------------------------------------------------

    def get_alert_sink(self) -> Callable[[Dict[str, Any]], Dict[str, Any]]:
        """Return a callable suitable for E4 AlertDispatcher.set_storage_sink().

        E4 calls sink(alert_dict) where alert_dict = AlertPayload.to_dict().

        Returns:
            Bound reference to self.store_alert.
        """
        return self.store_alert
