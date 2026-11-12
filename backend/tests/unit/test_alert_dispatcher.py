"""Unit tests for E4 Alert Dispatcher Module."""

import pytest

from src.engines.e4_alert_generation.alert_builder import AlertPayload
from src.engines.e4_alert_generation.alert_dispatcher import AlertDispatcher


def test_dispatcher_successful_delivery() -> None:
    """Tests successful dispatch to an E3 storage sink callable."""
    stored_alerts = []

    def mock_e3_sink(alert_dict):
        stored_alerts.append(alert_dict)
        return True

    dispatcher = AlertDispatcher(storage_sink=mock_e3_sink)

    alert = AlertPayload(
        alert_id="alt-001",
        result_id="res-001",
        alert_details={"event": "Deauth attack"},
        alert_timestamp="2026-11-12T12:00:00Z",
        severity="HIGH",
    )

    res = dispatcher.dispatch_alert(alert)

    assert res.is_successful is True
    assert res.attempts == 1
    assert len(stored_alerts) == 1
    assert stored_alerts[0]["alert_id"] == "alt-001"


def test_dispatcher_retry_on_transient_failure() -> None:
    """Tests bounded retries and recovery when E3 sink experiences transient failures."""
    call_count = 0
    stored_alerts = []

    def transient_failure_sink(alert_dict):
        nonlocal call_count
        call_count += 1
        if call_count < 2:
            raise ConnectionError("Transient E3 timeout")
        stored_alerts.append(alert_dict)
        return True

    dispatcher = AlertDispatcher(
        storage_sink=transient_failure_sink,
        max_retries=3,
        initial_delay=0.01,
    )

    alert = AlertPayload(
        alert_id="alt-002",
        result_id="res-002",
        alert_details={"event": "Beacon flood"},
        alert_timestamp="2026-11-12T12:00:00Z",
        severity="MEDIUM",
    )

    res = dispatcher.dispatch_alert(alert)

    assert res.is_successful is True
    assert res.attempts == 2
    assert len(stored_alerts) == 1


def test_dispatcher_failure_after_max_retries() -> None:
    """Tests that persistent failures are captured in DispatchResult without crashing."""
    def broken_e3_sink(alert_dict):
        raise RuntimeError("Permanent database down error")

    dispatcher = AlertDispatcher(
        storage_sink=broken_e3_sink,
        max_retries=2,
        initial_delay=0.01,
    )

    alert = AlertPayload(
        alert_id="alt-003",
        result_id="res-003",
        alert_details={"event": "Probe request flood"},
        alert_timestamp="2026-11-12T12:00:00Z",
        severity="LOW",
    )

    res = dispatcher.dispatch_alert(alert)

    assert res.is_successful is False
    assert res.attempts == 2
    assert "Permanent database down error" in res.error_message


def test_dispatcher_avoids_duplicate_dispatch() -> None:
    """Tests that already dispatched alert IDs are not re-sent to E3."""
    sink_invocations = 0

    def mock_sink(alert_dict):
        nonlocal sink_invocations
        sink_invocations += 1

    dispatcher = AlertDispatcher(storage_sink=mock_sink)

    alert = AlertPayload(
        alert_id="alt-004",
        result_id="res-004",
        alert_details={"event": "Auth attack"},
        alert_timestamp="2026-11-12T12:00:00Z",
        severity="HIGH",
    )

    # First dispatch
    res1 = dispatcher.dispatch_alert(alert)
    assert res1.is_successful is True
    assert sink_invocations == 1

    # Second dispatch of the exact same alert
    res2 = dispatcher.dispatch_alert(alert)
    assert res2.is_successful is True
    # Sink must not have been invoked a second time
    assert sink_invocations == 1


def test_dispatcher_no_direct_database_access() -> None:
    """Verifies that AlertDispatcher does not hold direct database connections or ORM sessions."""
    dispatcher = AlertDispatcher()
    assert not hasattr(dispatcher, "db")
    assert not hasattr(dispatcher, "engine")
    assert not hasattr(dispatcher, "session")

