"""E3: Data access repository for Log_Batch metadata."""

import uuid as _uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.database.models import Log_Batch
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class BatchRepository:
    """Read/write access for the Log_Batch entity.

    UUID mapping contract
    ----------------------
    batch_uuid  : UUID string supplied by E1 (batch_id field in E1StorageOutput
                  batch_metadata dict).  Never converted to an integer.
    batch_id    : Auto-increment integer primary key assigned by PostgreSQL.

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
        batch_uuid: _uuid.UUID,
        user_id: int,
        file_name: str,
        file_format: str,
        submitted_at: datetime,
        processing_status: str,
        total_records: int = 0,
        processed_records: int = 0,
        failed_records: int = 0,
    ) -> Log_Batch:
        """Persist a new Log_Batch record.

        Args:
            batch_uuid: Engine-generated UUID (from E1 batch_id field).
            user_id: Owning user's integer primary key.
            file_name: Original upload file name.
            file_format: File format/extension string.
            submitted_at: Timezone-aware submission datetime.
            processing_status: Status string (e.g. 'SUCCESS', 'FAILED').
            total_records: Total packet count.
            processed_records: Successfully processed count.
            failed_records: Failed/skipped count.

        Returns:
            Flushed Log_Batch ORM instance (no commit).

        Raises:
            IntegrityError: If batch_uuid already exists.
        """
        batch = Log_Batch(
            batch_uuid=batch_uuid,
            user_id=user_id,
            file_name=file_name,
            file_format=file_format,
            submitted_at=submitted_at,
            processing_status=processing_status,
            total_records=total_records,
            processed_records=processed_records,
            failed_records=failed_records,
        )
        try:
            self._session.add(batch)
            self._session.flush()
            logger.debug(
                "Created Log_Batch: batch_id=%d, batch_uuid=%s",
                batch.batch_id,
                batch_uuid,
            )
            return batch
        except IntegrityError:
            self._session.rollback()
            raise

    # ------------------------------------------------------------------
    # UUID mapping helpers
    # ------------------------------------------------------------------

    def get_internal_id_by_uuid(self, batch_uuid: _uuid.UUID) -> Optional[int]:
        """Resolve an external batch UUID to its internal integer primary key.

        Args:
            batch_uuid: Engine-generated batch UUID.

        Returns:
            Integer batch_id, or None if not found.
        """
        stmt = select(Log_Batch.batch_id).where(Log_Batch.batch_uuid == batch_uuid)
        return self._session.scalars(stmt).first()

    def get_by_uuid(self, batch_uuid: _uuid.UUID) -> Optional[Log_Batch]:
        """Return the Log_Batch ORM instance for a given batch UUID."""
        stmt = select(Log_Batch).where(Log_Batch.batch_uuid == batch_uuid)
        return self._session.scalars(stmt).first()

    def exists_by_uuid(self, batch_uuid: _uuid.UUID) -> bool:
        """Return True if a batch with the given UUID already exists."""
        stmt = select(Log_Batch.batch_id).where(Log_Batch.batch_uuid == batch_uuid)
        return self._session.scalars(stmt).first() is not None

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, batch_id: int) -> Optional[Log_Batch]:
        """Return a Log_Batch by its integer primary key."""
        return self._session.get(Log_Batch, batch_id)

    def list_by_user(
        self,
        user_id: int,
        offset: int = 0,
        limit: int = 50,
    ) -> List[Log_Batch]:
        """Return paginated batches belonging to a user, newest first.

        Args:
            user_id: Owning user's primary key.
            offset: Records to skip.
            limit: Maximum records to return (capped at 500).

        Returns:
            List of Log_Batch ORM instances.
        """
        limit = min(limit, 500)
        stmt = (
            select(Log_Batch)
            .where(Log_Batch.user_id == user_id)
            .order_by(Log_Batch.batch_id.desc())
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def update_status(
        self,
        batch_id: int,
        processing_status: str,
        total_records: Optional[int] = None,
        processed_records: Optional[int] = None,
        failed_records: Optional[int] = None,
    ) -> Optional[Log_Batch]:
        """Update the processing status (and optionally counters) of a batch.

        Args:
            batch_id: Batch's integer primary key.
            processing_status: New status string.
            total_records: Updated total count (optional).
            processed_records: Updated success count (optional).
            failed_records: Updated failure count (optional).

        Returns:
            Updated Log_Batch, or None if not found.
        """
        batch = self.get_by_id(batch_id)
        if batch is None:
            logger.warning("update_status: batch_id=%d not found.", batch_id)
            return None
        batch.processing_status = processing_status
        if total_records is not None:
            batch.total_records = total_records
        if processed_records is not None:
            batch.processed_records = processed_records
        if failed_records is not None:
            batch.failed_records = failed_records
        self._session.flush()
        return batch
