"""E3: Data access repository for Detection_Rule definitions."""

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.src.database.models import Detection_Rule
from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class RuleRepository:
    """Read/write access for the Detection_Rule entity.

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
        rule_name: str,
        suspicious_activity: str,
        protocol: str,
        detection_condition: str,
        severity: str,
        threshold_value: Optional[float] = None,
        time_window_seconds: Optional[int] = None,
        is_enabled: bool = True,
    ) -> Detection_Rule:
        """Persist a new Detection_Rule record.

        Args:
            rule_name: Unique rule identifier string.
            suspicious_activity: Threat category label.
            protocol: Applicable network protocol.
            detection_condition: Textual description of the matching condition.
            severity: Severity level string ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
            threshold_value: Optional numeric threshold.
            time_window_seconds: Optional observation window in seconds.
            is_enabled: Whether the rule is active (default True).

        Returns:
            Flushed Detection_Rule ORM instance (no commit).

        Raises:
            IntegrityError: If rule_name already exists.
        """
        rule = Detection_Rule(
            rule_name=rule_name,
            suspicious_activity=suspicious_activity,
            protocol=protocol,
            detection_condition=detection_condition,
            severity=severity,
            threshold_value=threshold_value,
            time_window_seconds=time_window_seconds,
            is_enabled=is_enabled,
        )
        try:
            self._session.add(rule)
            self._session.flush()
            logger.debug("Created Detection_Rule: rule_id=%d, rule_name=%s", rule.rule_id, rule_name)
            return rule
        except IntegrityError:
            self._session.rollback()
            raise

    # ------------------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------------------

    def get_by_id(self, rule_id: int) -> Optional[Detection_Rule]:
        """Return a Detection_Rule by its integer primary key."""
        return self._session.get(Detection_Rule, rule_id)

    def get_by_name(self, rule_name: str) -> Optional[Detection_Rule]:
        """Return a Detection_Rule by its unique name, or None if absent."""
        stmt = select(Detection_Rule).where(Detection_Rule.rule_name == rule_name)
        return self._session.scalars(stmt).first()

    # ------------------------------------------------------------------
    # E2 interface: retrieve enabled rules
    # ------------------------------------------------------------------

    def get_enabled_rules(self) -> List[Detection_Rule]:
        """Return all enabled Detection_Rule records for E2 processing.

        Returns:
            List of Detection_Rule ORM instances where is_enabled=True,
            ordered by rule_id for deterministic evaluation order.
        """
        stmt = (
            select(Detection_Rule)
            .where(Detection_Rule.is_enabled.is_(True))
            .order_by(Detection_Rule.rule_id)
        )
        rules = list(self._session.scalars(stmt).all())
        logger.debug("get_enabled_rules: returned %d rules.", len(rules))
        return rules

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def list_all(
        self,
        offset: int = 0,
        limit: int = 100,
    ) -> List[Detection_Rule]:
        """Return a paginated list of all detection rules.

        Args:
            offset: Records to skip.
            limit: Maximum records to return (capped at 1000).

        Returns:
            List of Detection_Rule ORM instances.
        """
        limit = min(limit, 1000)
        stmt = (
            select(Detection_Rule)
            .order_by(Detection_Rule.rule_id)
            .offset(offset)
            .limit(limit)
        )
        return list(self._session.scalars(stmt).all())

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def set_enabled(self, rule_id: int, is_enabled: bool) -> Optional[Detection_Rule]:
        """Enable or disable a detection rule.

        Args:
            rule_id: Rule's integer primary key.
            is_enabled: New enabled state.

        Returns:
            Updated Detection_Rule, or None if not found.
        """
        rule = self.get_by_id(rule_id)
        if rule is None:
            logger.warning("set_enabled: rule_id=%d not found.", rule_id)
            return None
        rule.is_enabled = is_enabled
        self._session.flush()
        return rule
