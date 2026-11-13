"""E3: Data access repository for Traffic_Log records."""

import uuid as _uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.database.models import Traffic_Log
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class LogRepository:
    """Read/write access for the Traffic_Log entity.

    UUID mapping contract
    ----------------------
    log_uuid  : UUID string supplied by E1 (log_id field in ProcessedRecord /
                E1StorageOutput traffic_logs list).  Never converted to an integer.
    log_id    : Auto-increment BigInteger primary key assigned by PostgreSQL.

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
        log_uuid: _uuid.UUID,
        batch_id: int,
        timestamp: datetime,
        source_address: str,
        destination_address: str,
        protocol: str,
        source_mac: Optional[str] = None,
        destination_mac: Optional[str] = None,
        log_details: Optional[str] = None,
    ) -> Traffic_Log:
        """Persist a single Traffic_Log record.

        Args:
            log_uuid: Engine-generated UUID (from E1 log_id field).
            batch_id: Internal integer FK to log_batches.batch_id.
            timestamp: Timezone-aware event timestamp.
            source_address: Source IP/address string.
            destination_address: Destination IP/address string.
            protocol: Network protocol string.
            source_mac: Optional source MAC address.
            destination_mac: Optional destination MAC address.
            log_details: Optional JSON-serialized Text details.

        Returns:
            Flushed Traffic_Log ORM instance (no commit).

        Raises:
            IntegrityError: If log_uuid already exists.
        """
        log = Traffic_Log(
            log_uuid=log_uuid,
            batch_id=batch_id,
            timestamp=timestamp,
            source_address=source_address,
            destination_address=destination_address,
            protocol=protocol,
            source_mac=source_mac,
            destination_mac=destination_mac,
            log_details=log_details,
        )
        try:
            self._session.add(log)
            self._session.flush()
            logger.debug(
                "Created Traffic_Log: log_id=%d, log_uuid=%s",
                log.log_id,
                log_uuid,
            )
            return log
        except IntegrityError:
            self._session.rollback()
            raise

    def bulk_create(self, records: List[dict]) -> List[Traffic_Log]:
        """Persist a list of Traffic_Log records efficiently.

        Each dict must contain keys matching the create() signature.
        Records with duplicate log_uuids are skipped with a warning.

        Args:
            records: List of Traffic_Log attribute dicts.

        Returns:
            List of successfully flushed Traffic_Log ORM instances.
        """
        created: List[Traffic_Log] = []
        for rec in records:
            log_uuid = rec.get("log_uuid")
            if log_uuid and self.exists_by_uuid(log_uuid):
                logger.warning(
                    "bulk_create: skipping duplicate log_uuid=%s", log_uuid
                )
                continue
            obj = Traffic_Log(
                log_uuid=rec["log_uuid"],
                batch_id=rec["batch_id"],
                timestamp=rec["timestamp"],
                source_address=rec["source_address"],
                destination_address=rec["destination_address"],
                protocol=rec["protocol"],
                source_mac=rec.get("source_mac"),
                destination_mac=rec.get("destination_mac"),
                log_details=rec.get("log_details"),
            )
            self._session.add(obj)
            created.append(obj)
        if created:
            self._session.flush()
        logger.debug("bulk_create: persisted %d traffic_log records.", len(created))
        return created

    # ------------------------------------------------------------------
    # UUID mapping helpers
    # ------------------------------------------------------------------

    def get_internal_id_by_uuid(self, log_uuid: _uuid.UUID) -> Optional[int]:
        """Resolve an external log UUID to its internal BigInteger primary key."""
        stmt = select(Traffic_Log.log_id).where(Traffic_Log.log_uuid == log_uuid)
        return self._session.scalars(stmt).first()

    def get_by_uuid(self, log_uuid: _uuid.UUID) -> Optional[Traffic_Log]:
        """Return the Traffic_Log ORM instance for a given log UUID."""
        stmt = select(Traffic_Log).where(Traffic_Log.log_uuid == log_uuid)
        return self._session.scalars(stmt).first()

    def exists_by_uuid(self, log_uuid: _uuid.UUID) -> bool:
        """Return True if a traffic_log with the given UUID already exists."""
        stmt = select(Traffic_Log.log_id).where(Traffic_Log.log_uuid == log_uuid)
        return self._session.scalars(stmt).first() is not None

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, log_id: int) -> Optional[Traffic_Log]:
        """Return a Traffic_Log by its BigInteger primary key."""
        return self._session.get(Traffic_Log, log_id)

    def list_by_batch(
        self,
        batch_id: int,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Traffic_Log]:
        """Return paginated traffic logs for a batch, ordered by log_id.

        Args:
            batch_id: Owning batch's integer FK.
            offset: Records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of Traffic_Log ORM instances.
        """
        limit = min(limit, 1000)
        stmt = (
            select(Traffic_Log)
            .where(Traffic_Log.batch_id == batch_id)
            .order_by(Traffic_Log.log_id)
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())
