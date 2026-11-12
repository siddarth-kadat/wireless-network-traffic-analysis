"""Integration tests for the complete E4 Alert Generation Engine."""

import pytest

from src.common.constants import AlertStatus, SeverityLevel
from src.engines.e4_alert_generation import E4AlertEngine


def test_e4_full_pipeline_suspicious_result() -> None:
    """Requirement 1, 7, 8, 9, 10, 12: Suspicious result generates alert and forwards to E3."""
    dispatched_alerts = []

    def mock_e3_storage(alert_dict):
        dispatched_alerts.append(alert_dict)
        return True

    engine = E4AlertEngine(storage_sink=mock_e3_storage)

    detection_result = {
        "result_id": "e2-result-1001",
        "log_id": "log-entry-55",
        "rule_id": "RULE-WIFI-DEAUTH",
        "rule_name": "Mass Deauthentication Attack Detector",
        "suspicious_activity": "Deauthentication Flood",
        "rule_match_status": True,  # Confirmed suspicious
        "observed_value": 120,
        "threshold_value": 30,
        "severity": "HIGH",
        "detection_evidence": {"frame_delta_ms": 2.5, "burst_count": 120},
        "source_mac": "00:14:22:01:23:45",
        "destination_mac": "ff:ff:ff:ff:ff:ff",
        "protocol": "802.11_MGMT",
    }

    alert, reason = engine.process_result(detection_result)

    # 1. Alert generated
    assert alert is not None
    assert reason is None
    assert alert.alert_id is not None

    # 2. Correct mapping
    assert alert.result_id == "e2-result-1001"
    assert alert.severity == SeverityLevel.HIGH.value
    assert alert.alert_status == AlertStatus.NEW.value
    assert alert.alert_timestamp is not None

    # 3. Dispatched to E3
    assert len(dispatched_alerts) == 1
    stored = dispatched_alerts[0]
    assert stored["alert_id"] == alert.alert_id
    assert stored["result_id"] == "e2-result-1001"
    assert stored["alert_details"]["suspicious_activity"] == "Deauthentication Flood"
    assert stored["alert_details"]["network_context"]["source_mac"] == "00:14:22:01:23:45"


def test_e4_normal_result_no_alert() -> None:
    """Requirement 2: Normal/clean detection result does not generate an alert."""
    dispatched_alerts = []
    engine = E4AlertEngine(storage_sink=lambda a: dispatched_alerts.append(a))

    normal_result = {
        "result_id": "e2-result-normal",
        "rule_match_status": False,  # Normal / clean traffic
        "severity": "LOW",
    }

    alert, reason = engine.process_result(normal_result)

    assert alert is None
    assert "normal" in reason.lower()
    assert len(dispatched_alerts) == 0


def test_e4_invalid_and_missing_result_id() -> None:
    """Requirement 3, 4: Invalid detection result and missing result_id handled correctly."""
    engine = E4AlertEngine()

    # Missing result_id
    invalid_result = {
        "rule_match_status": True,
        "severity": "MEDIUM",
    }
    alert, reason = engine.process_result(invalid_result)
    assert alert is None
    assert "result_id" in reason.lower()

    # None input
    alert_none, reason_none = engine.process_result(None)
    assert alert_none is None
    assert "none" in reason_none.lower()


def test_e4_missing_severity_and_network_info() -> None:
    """Requirement 5, 6: Missing severity uses fallback; missing network info does not crash."""
    engine = E4AlertEngine()

    result_no_net = {
        "result_id": "res-no-net",
        "rule_match_status": True,
        "severity": None,  # Missing severity
        # No IP, MAC, or protocol provided
    }

    alert, reason = engine.process_result(result_no_net)

    assert alert is not None
    assert alert.severity == SeverityLevel.MEDIUM.value  # Default fallback
    assert alert.alert_details["network_context"]["source_address"] is None
    assert alert.alert_details["network_context"]["source_mac"] is None


def test_e4_duplicate_detection_results() -> None:
    """Requirement 11, 14: Duplicate detection results do not generate duplicate alerts."""
    dispatched_alerts = []
    engine = E4AlertEngine(storage_sink=lambda a: dispatched_alerts.append(a))

    result = {
        "result_id": "res-repeat-01",
        "rule_match_status": True,
        "severity": "CRITICAL",
    }

    # First attempt: generates alert
    alert1, reason1 = engine.process_result(result)
    assert alert1 is not None
    assert reason1 is None
    assert len(dispatched_alerts) == 1

    # Second attempt with same result_id: must be rejected as duplicate
    alert2, reason2 = engine.process_result(result)
    assert alert2 is None
    assert "duplicate" in reason2.lower()
    assert len(dispatched_alerts) == 1  # No duplicate dispatch


def test_e4_batch_processing_fault_isolation() -> None:
    """Requirement 15: Batch processing handles valid, normal, and invalid records independently."""
    dispatched_alerts = []
    engine = E4AlertEngine(storage_sink=lambda a: dispatched_alerts.append(a))

    batch = [
        # 1. Valid suspicious result -> should generate alert
        {
            "result_id": "batch-res-1",
            "rule_match_status": True,
            "severity": "HIGH",
            "suspicious_activity": "Beacon Flood",
        },
        # 2. Normal traffic result -> should be skipped
        {
            "result_id": "batch-res-2",
            "rule_match_status": False,
            "severity": "LOW",
        },
        # 3. Invalid record (missing result_id) -> should be rejected
        {
            "rule_match_status": True,
        },
        # 4. Duplicate of res-1 -> should be skipped
        {
            "result_id": "batch-res-1",
            "rule_match_status": True,
            "severity": "HIGH",
        },
        # 5. Second valid suspicious result -> should generate alert
        {
            "result_id": "batch-res-3",
            "rule_match_status": True,
            "severity": "CRITICAL",
            "suspicious_activity": "Rogue AP",
        },
    ]

    alerts, summary = engine.process_batch(batch)

    assert len(alerts) == 2
    assert summary.total_results_received == 5
    assert summary.suspicious_results_identified == 2
    assert summary.normal_results_skipped == 1
    assert summary.invalid_results_rejected == 1
    assert summary.duplicate_results_skipped == 1
    assert summary.alerts_generated == 2
    assert summary.alerts_dispatched == 2
    assert len(dispatched_alerts) == 2


def test_e4_e3_communication_failure_and_retries() -> None:
    """Requirement 13: E3 communication failure is retried and reported without crashing."""
    attempts = 0

    def failing_e3_sink(alert_dict):
        nonlocal attempts
        attempts += 1
        raise ConnectionResetError("E3 database connection lost")

    engine = E4AlertEngine(storage_sink=failing_e3_sink, max_retries=3)

    result = {
        "result_id": "res-fail-test",
        "rule_match_status": True,
        "severity": "HIGH",
    }

    alert, reason = engine.process_result(result)

    # Alert was generated but dispatch failed after retries
    assert alert is not None
    assert reason is not None
    assert "dispatch warning" in reason.lower()
    assert attempts == 3


def test_e4_no_direct_database_access() -> None:
    """Requirement 16: Verifies E4 does not import or use direct SQLAlchemy or SQLite database connections."""
    import sys
    engine = E4AlertEngine()

    # Verify no database connection object exists on E4 engine or its components
    assert not hasattr(engine, "db")
    assert not hasattr(engine, "session")
    assert not hasattr(engine, "engine_connection")
    assert not hasattr(engine.dispatcher, "db")
    assert not hasattr(engine.generator, "db")

