"""Coordination: Inter-Engine Message and Event Handler.

Provides publish-subscribe event routing, in-memory event auditing, and
asynchronous/synchronous message dispatching across E1, E2, E3, and E4.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from backend.src.common.logger import get_logger

logger = get_logger(__name__)


class EventType(str, Enum):
    """Supported inter-engine coordination event types."""

    PCAP_INGESTION_STARTED = "PCAP_INGESTION_STARTED"
    PCAP_INGESTION_COMPLETED = "PCAP_INGESTION_COMPLETED"
    LOGS_STORED = "LOGS_STORED"
    DETECTION_STARTED = "DETECTION_STARTED"
    DETECTION_COMPLETED = "DETECTION_COMPLETED"
    ALERT_GENERATED = "ALERT_GENERATED"
    PIPELINE_COMPLETED = "PIPELINE_COMPLETED"
    PIPELINE_FAILED = "PIPELINE_FAILED"


@dataclass
class CoordinationEvent:
    """Encapsulates an event dispatched across engine coordination boundaries."""

    event_type: EventType
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    batch_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    message: str = ""


EventListener = Callable[[CoordinationEvent], None]


class MessageHandler:
    """Central event broker for inter-engine notifications and audit tracking."""

    def __init__(self, max_event_history: int = 1000) -> None:
        self._listeners: Dict[EventType, List[EventListener]] = {
            evt: [] for evt in EventType
        }
        self._wildcard_listeners: List[EventListener] = []
        self._history: List[CoordinationEvent] = []
        self._max_history = max_event_history

    def subscribe(
        self,
        event_type: Optional[EventType],
        listener: EventListener,
    ) -> None:
        """Subscribe a listener callback to an event type (or all if event_type is None)."""
        if event_type is None:
            self._wildcard_listeners.append(listener)
        else:
            self._listeners[event_type].append(listener)

    def unsubscribe(
        self,
        event_type: Optional[EventType],
        listener: EventListener,
    ) -> None:
        """Remove a previously subscribed listener callback."""
        if event_type is None:
            if listener in self._wildcard_listeners:
                self._wildcard_listeners.remove(listener)
        elif event_type in self._listeners:
            if listener in self._listeners[event_type]:
                self._listeners[event_type].remove(listener)

    def publish(
        self,
        event_type: EventType,
        batch_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        message: str = "",
    ) -> CoordinationEvent:
        """Create and dispatch a coordination event to all matching subscribers."""
        event = CoordinationEvent(
            event_type=event_type,
            batch_id=batch_id,
            payload=payload or {},
            message=message,
        )

        # Audit history
        self._history.append(event)
        if len(self._history) > self._max_history:
            self._history.pop(0)

        logger.debug(
            "CoordinationEvent published: type=%s, batch_id=%s, msg='%s'",
            event_type.value,
            batch_id,
            message,
        )

        # Notify specific listeners
        for listener in self._listeners.get(event_type, []):
            try:
                listener(event)
            except Exception as exc:
                logger.error(
                    "Error executing listener for event %s: %s", event_type.value, exc
                )

        # Notify wildcard listeners
        for listener in self._wildcard_listeners:
            try:
                listener(event)
            except Exception as exc:
                logger.error(
                    "Error executing wildcard listener for event %s: %s",
                    event_type.value,
                    exc,
                )

        return event

    def get_history(
        self,
        batch_id: Optional[str] = None,
        event_type: Optional[EventType] = None,
        limit: int = 100,
    ) -> List[CoordinationEvent]:
        """Query in-memory event audit log."""
        results = self._history
        if batch_id:
            results = [e for e in results if e.batch_id == batch_id]
        if event_type:
            results = [e for e in results if e.event_type == event_type]
        return results[-limit:]

    def clear(self) -> None:
        """Clear event history."""
        self._history.clear()


# Shared singleton broker for application-wide coordination
default_message_handler = MessageHandler()
