"""Unit tests for E4 Alert Builder and Formatter Modules."""

import pytest

from src.common.constants import AlertStatus
from src.engines.e4_alert_generation.alert_builder import AlertBuilder, AlertPayload
from src.engines.e4_alert_generation.alert_formatter import AlertFormatter
from src.engines.e4_alert_generation.alert_receiver import DetectionResultPayload


def test_alert_builder_schema_compliance() -> None:
    """Tests that AlertBuilder creates an AlertPayload adhering to the Alert entity schema."""
    builder = AlertBuilder()

    payload = DetectionResultPayload(
        result_id="res-201",
        rule_match_status=True,
        log_id="log-888",
        rule_id="R-BRUTE-01",
        rule_name="WPA Handshake Brute Force Detection",
        suspicious_activity="Authentication Brute Force",
        severity="HIGH",
        observed_value=25,
        threshold_value=5,
        source_mac="00:11:22:33:44:55",
        destination_mac="66:77:88:99:aa:bb",
        protocol="802.11_MGMT",
        detection_evidence={"failed_auth_attempts": 25},
    )

    alert = builder.build_alert(payload, severity="HIGH")

    assert isinstance(alert, AlertPayload)
    assert alert.alert_id is not None
    assert alert.result_id == "res-201"
    assert alert.severity == "HIGH"
    assert alert.alert_status == AlertStatus.NEW.value
    assert alert.alert_timestamp is not None

    alert_dict = alert.to_dict()
    expected_keys = {
        "alert_id",
        "result_id",
        "alert_details",
        "alert_timestamp",
        "severity",
        "alert_status",
    }
    assert set(alert_dict.keys()) == expected_keys

    details = alert_dict["alert_details"]
    assert details["rule_id"] == "R-BRUTE-01"
    assert details["log_id"] == "log-888"
    assert details["network_context"]["source_mac"] == "00:11:22:33:44:55"
    assert details["metrics"]["observed_value"] == 25
    assert details["metrics"]["threshold_value"] == 5


def test_alert_builder_missing_optional_fields_no_fabrication() -> None:
    """Tests that missing optional network fields remain None and do not crash alert generation."""
    builder = AlertBuilder()

    payload = DetectionResultPayload(
        result_id="res-202",
        rule_match_status=True,
        rule_id="R-ANOMALY-02",
        # All network fields are None
        source_address=None,
        destination_address=None,
        source_mac=None,
        destination_mac=None,
        protocol=None,
    )

    alert = builder.build_alert(payload, severity="MEDIUM")

    assert alert is not None
    assert alert.result_id == "res-202"
    details = alert.alert_details
    assert details["network_context"]["source_address"] is None
    assert details["network_context"]["source_mac"] is None


def test_alert_formatter_sanitizes_html_and_injection() -> None:
    """Tests that alert descriptions escape HTML and injection patterns."""
    formatter = AlertFormatter()

    dangerous_text = "<script>alert('xss')</script> & 'admin' OR 1=1"
    sanitized = formatter.sanitize_text(dangerous_text)

    assert "<script>" not in sanitized
    assert "&lt;script&gt;" in sanitized
    assert "&amp;" in sanitized

