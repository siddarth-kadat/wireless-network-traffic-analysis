"""E3: Data access repository for Alert records."""

import uuid as _uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.database.models import Alert
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class AlertRepository:
    """Read/write access for the Alert entity.

    UUID mapping contract
    ----------------------
    alert_uuid : UUID string supplied by E4 (alert_id field in AlertPayload).
                 Never converted to an integer.
    alert_id   : Auto-increment Integer primary key assigned by PostgreSQL.
    result_id  : Internal BigInteger FK to detection_results.result_id.
                 Resolved from E4's result_id (which is E2's result_uuid) via
                 ResultRepository.get_internal_id_by_uuid() before calling this repository.

    Cardinality: Detection_Result → Alert is 1-to-0-or-1 (enforced by unique FK on result_id).

    Transaction ownership lies with the calling service; this repository does
    NOT call session.commit().
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def create(
        self,
        alert_uuid: _uuid.UUID,
        result_id: int,
        alert_details: str,
        alert_timestamp: datetime,
        severity: str,
        alert_status: str,
    ) -> Alert:
        """Persist a new Alert record.

        Args:
            alert_uuid: E4-generated UUID (from AlertPayload.alert_id).
            result_id: Internal BigInteger FK to detection_results.result_id.
            alert_details: JSON-serialized alert details string.
            alert_timestamp: Timezone-aware alert creation datetime.
            severity: Severity string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
            alert_status: Status string (e.g. 'NEW', 'ACKNOWLEDGED', 'RESOLVED').

        Returns:
            Flushed Alert ORM instance (no commit).

        Raises:
            IntegrityError: If alert_uuid or result_id already exists (unique constraints).
        """
        alert = Alert(
            alert_uuid=alert_uuid,
            result_id=result_id,
            alert_details=alert_details,
            alert_timestamp=alert_timestamp,
            severity=severity,
            alert_status=alert_status,
        )
        try:
            self._session.add(alert)
            self._session.flush()
            logger.debug(
                "Created Alert: alert_id=%d, alert_uuid=%s, result_id=%d",
                alert.alert_id,
                alert_uuid,
                result_id,
            )
            return alert
        except IntegrityError:
            self._session.rollback()
            raise

    # ------------------------------------------------------------------
    # UUID mapping helpers
    # ------------------------------------------------------------------

    def get_by_uuid(self, alert_uuid: _uuid.UUID) -> Optional[Alert]:
        """Return the Alert ORM instance for a given alert UUID."""
        stmt = select(Alert).where(Alert.alert_uuid == alert_uuid)
        return self._session.scalars(stmt).first()

    def exists_by_uuid(self, alert_uuid: _uuid.UUID) -> bool:
        """Return True if an alert with the given UUID already exists."""
        stmt = select(Alert.alert_id).where(Alert.alert_uuid == alert_uuid)
        return self._session.scalars(stmt).first() is not None

    def exists_for_result(self, result_id: int) -> bool:
        """Return True if an alert already exists for the given detection result.

        Used to enforce the 1-to-0-or-1 cardinality at the application level.

        Args:
            result_id: Internal BigInteger FK to detection_results.result_id.

        Returns:
            True if an alert already exists for this result.
        """
        stmt = select(Alert.alert_id).where(Alert.result_id == result_id)
        return self._session.scalars(stmt).first() is not None

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, alert_id: int) -> Optional[Alert]:
        """Return an Alert by its integer primary key."""
        return self._session.get(Alert, alert_id)

    def get_by_result_id(self, result_id: int) -> Optional[Alert]:
        """Return the Alert associated with a detection result, or None."""
        stmt = select(Alert).where(Alert.result_id == result_id)
        return self._session.scalars(stmt).first()

    def list_all(
        self,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """Return paginated alerts ordered newest-first.

        Args:
            offset: Records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of Alert ORM instances.
        """
        limit = min(limit, 1000)
        stmt = (
            select(Alert)
            .order_by(Alert.alert_id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())

    def list_by_severity(
        self,
        severity: str,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Alert]:
        """Return paginated alerts for a specific severity level.

        Args:
            severity: Severity string filter.
            offset: Records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of Alert ORM instances.
        """
        limit = min(limit, 1000)
        stmt = (
            select(Alert)
            .where(Alert.severity == severity)
            .order_by(Alert.alert_id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_status(self, alert_id: int, alert_status: str) -> Optional[Alert]:
        """Update an alert's status.

        Args:
            alert_id: Alert's integer primary key.
            alert_status: New status string.

        Returns:
            Updated Alert instance, or None if not found.
        """
        alert = self.get_by_id(alert_id)
        if alert is None:
            logger.warning("update_status: alert_id=%d not found.", alert_id)
            return None
        alert.alert_status = alert_status
        self._session.flush()
        return alert
