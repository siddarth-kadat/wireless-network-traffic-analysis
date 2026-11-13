"""E3: Data access repository for Processing_Error records."""

import uuid as _uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.database.models import Processing_Error
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class ErrorRepository:
    """Read/write access for the Processing_Error entity.

    UUID mapping contract
    ----------------------
    error_uuid : UUID string supplied by E1 (error_id field in ProcessingErrorRecord).
                 Never converted to an integer.
    error_id   : Auto-increment BigInteger primary key assigned by PostgreSQL.

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
        error_uuid: _uuid.UUID,
        batch_id: int,
        error_type: str,
        error_message: str,
        error_timestamp: datetime,
        log_id: Optional[int] = None,
    ) -> Processing_Error:
        """Persist a single Processing_Error record.

        Args:
            error_uuid: E1-generated UUID (from ProcessingErrorRecord.error_id field).
            batch_id: Internal integer FK to log_batches.batch_id.
            error_type: Error category string (e.g. 'PacketParsingCorruption').
            error_message: Human-readable error description.
            error_timestamp: Timezone-aware error occurrence datetime.
            log_id: Optional internal BigInteger FK to traffic_logs.log_id
                    (None when the error is not associated with a specific log).

        Returns:
            Flushed Processing_Error ORM instance (no commit).

        Raises:
            IntegrityError: If error_uuid already exists.
        """
        error = Processing_Error(
            error_uuid=error_uuid,
            batch_id=batch_id,
            log_id=log_id,
            error_type=error_type,
            error_message=error_message,
            error_timestamp=error_timestamp,
        )
        try:
            self._session.add(error)
            self._session.flush()
            logger.debug(
                "Created Processing_Error: error_id=%d, error_uuid=%s, type=%s",
                error.error_id,
                error_uuid,
                error_type,
            )
            return error
        except IntegrityError:
            self._session.rollback()
            raise

    def bulk_create(self, records: List[dict]) -> List[Processing_Error]:
        """Persist a list of Processing_Error records efficiently.

        Each dict must contain keys matching the create() signature.
        Records with duplicate error_uuids are skipped with a warning.

        Args:
            records: List of Processing_Error attribute dicts.

        Returns:
            List of successfully flushed Processing_Error ORM instances.
        """
        created: List[Processing_Error] = []
        for rec in records:
            error_uuid = rec.get("error_uuid")
            if error_uuid and self.exists_by_uuid(error_uuid):
                logger.warning(
                    "bulk_create: skipping duplicate error_uuid=%s", error_uuid
                )
                continue
            obj = Processing_Error(
                error_uuid=rec["error_uuid"],
                batch_id=rec["batch_id"],
                log_id=rec.get("log_id"),
                error_type=rec["error_type"],
                error_message=rec["error_message"],
                error_timestamp=rec["error_timestamp"],
            )
            self._session.add(obj)
            created.append(obj)
        if created:
            self._session.flush()
        logger.debug("bulk_create: persisted %d processing_error records.", len(created))
        return created

    # ------------------------------------------------------------------
    # UUID helpers
    # ------------------------------------------------------------------

    def get_by_uuid(self, error_uuid: _uuid.UUID) -> Optional[Processing_Error]:
        """Return the Processing_Error ORM instance for a given error UUID."""
        stmt = select(Processing_Error).where(
            Processing_Error.error_uuid == error_uuid
        )
        return self._session.scalars(stmt).first()

    def exists_by_uuid(self, error_uuid: _uuid.UUID) -> bool:
        """Return True if a processing_error with the given UUID already exists."""
        stmt = select(Processing_Error.error_id).where(
            Processing_Error.error_uuid == error_uuid
        )
        return self._session.scalars(stmt).first() is not None

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, error_id: int) -> Optional[Processing_Error]:
        """Return a Processing_Error by its BigInteger primary key."""
        return self._session.get(Processing_Error, error_id)

    def list_by_batch(
        self,
        batch_id: int,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Processing_Error]:
        """Return paginated errors for a batch, ordered by error_id.

        Args:
            batch_id: Owning batch's integer FK.
            offset: Records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of Processing_Error ORM instances.
        """
        limit = min(limit, 1000)
        stmt = (
            select(Processing_Error)
            .where(Processing_Error.batch_id == batch_id)
            .order_by(Processing_Error.error_id)
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())
