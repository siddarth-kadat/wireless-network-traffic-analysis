"""Unit tests for E2 detection algorithms (A04 - A11).

Tests all eight approved deterministic algorithms for match, non-match,
boundary conditions, missing fields, and evidence generation.
"""

import time
import uuid
from typing import Any, Dict
import pytest

from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from backend.src.engines.e2_suspicious_pattern_detection.pattern_identifier import (
    PatternIdentifier,
)
from backend.src.engines.e2_suspicious_pattern_detection.signature_detector import (
    SignatureDetector,
)
from backend.src.engines.e2_suspicious_pattern_detection.statistical_detector import (
    StatisticalDetector,
)
from backend.src.engines.e2_suspicious_pattern_detection.threshold_detector import (
    ThresholdDetector,
)


def _make_sample_record(
    log_id: str = None,
    protocol: str = "802.11_MGMT",
    src_addr: str = "192.168.1.100",
    dst_addr: str = "192.168.1.1",
    src_mac: str = "00:11:22:33:44:55",
    dst_mac: str = "66:77:88:99:aa:bb",
    timestamp: str = "2026-11-12T17:00:00+00:00",
    frame_type: str = "Management",
    frame_subtype: str = "Deauthentication",
    dst_port: int = 80,
    packet_length: int = 120,
) -> ProcessedRecord:
    """Helper to create a ProcessedRecord for testing."""
    return ProcessedRecord(
        log_id=log_id or str(uuid.uuid4()),
        batch_id=str(uuid.uuid4()),
        timestamp=timestamp,
        source_address=src_addr,
        destination_address=dst_addr,
        source_mac=src_mac,
        destination_mac=dst_mac,
        protocol=protocol,
        log_details={
            "packet_index": 1,
            "packet_length": packet_length,
            "captured_length": packet_length,
            "link_layer_type": "IEEE 802.11 RadioTap",
            "destination_port": dst_port,
            "source_port": 54321,
            "wireless": {
                "bssid": "00:14:22:01:23:45",
                "ssid": "TestLabNetwork",
                "frame_type": frame_type,
                "frame_subtype": frame_subtype,
                "channel": 6,
                "signal_strength": -65,
            },
        },
    )


# ===========================================================================
# A04: Rule-Based Pattern Matching
# ===========================================================================

class TestA04RuleBasedPatternMatching:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_a04_exact_match(self):
        rec = _make_sample_record(frame_subtype="Deauthentication")
        cond = {"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}
        matched, evidence = self.detector.evaluate_pattern(rec, "802.11_MGMT", cond)
        assert matched is True
        assert evidence["matched"] is True
        assert evidence["protocol_matched"] is True

    def test_a04_non_match_different_value(self):
        rec = _make_sample_record(frame_subtype="Beacon")
        cond = {"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}
        matched, evidence = self.detector.evaluate_pattern(rec, "802.11_MGMT", cond)
        assert matched is False

    def test_a04_non_match_protocol_mismatch(self):
        rec = _make_sample_record(protocol="TCP")
        cond = {"field": "dst_port", "operator": "eq", "value": 80}
        matched, evidence = self.detector.evaluate_pattern(rec, "UDP", cond)
        assert matched is False
        assert evidence["protocol_matched"] is False

    def test_a04_string_expression_condition(self):
        rec = _make_sample_record(dst_port=22)
        matched, evidence = self.detector.evaluate_pattern(rec, "ANY", "dst_port == 22")
        assert matched is True

    def test_a04_relational_operators(self):
        rec = _make_sample_record(packet_length=1500)
        matched_gt, _ = self.detector.evaluate_pattern(rec, "ANY", "packet_length > 1000")
        assert matched_gt is True
        matched_lt, _ = self.detector.evaluate_pattern(rec, "ANY", "packet_length < 1000")
        assert matched_lt is False

    def test_a04_membership_and_regex(self):
        rec = _make_sample_record(frame_subtype="Probe Request")
        cond_in = {"field": "frame_subtype", "operator": "in", "value": ["Probe Request", "Beacon"]}
        matched_in, _ = self.detector.evaluate_pattern(rec, "ANY", cond_in)
        assert matched_in is True

        cond_regex = {"field": "frame_subtype", "operator": "regex", "value": r"^Probe.*"}
        matched_regex, _ = self.detector.evaluate_pattern(rec, "ANY", cond_regex)
        assert matched_regex is True


# ===========================================================================
# A05: Sliding Window Threshold Detection
# ===========================================================================

class TestA05SlidingWindowThreshold:
    def setup_method(self):
        self.detector = ThresholdDetector()

    def test_a05_threshold_exceeded(self):
        base_ts = 1700000000.0
        # Fire 5 events in window with threshold=4
        matched = False
        for i in range(5):
            rec = _make_sample_record(
                src_addr="192.168.1.50",
                timestamp=str(base_ts + i * 2),  # 2-second intervals
            )
            matched, obs, thresh, ev = self.detector.evaluate_sliding_window_threshold(
                record=rec, threshold=4.0, window_seconds=60, group_by_field="source_address"
            )

        assert matched is True
        assert obs == 5.0
        assert thresh == 4.0
        assert ev["matched"] is True

    def test_a05_threshold_not_exceeded(self):
        rec = _make_sample_record(src_addr="192.168.1.51", timestamp="2026-11-12T17:00:00+00:00")
        matched, obs, thresh, ev = self.detector.evaluate_sliding_window_threshold(
            record=rec, threshold=10.0, window_seconds=30
        )
        assert matched is False
        assert obs == 1.0

    def test_a05_event_expiration(self):
        base_ts = 1700000000.0
        # Add 3 events at t=0
        for _ in range(3):
            rec = _make_sample_record(src_addr="192.168.1.52", timestamp=str(base_ts))
            self.detector.evaluate_sliding_window_threshold(rec, threshold=5.0, window_seconds=10)

        # Add 1 event at t=15 (earlier 3 events expired)
        rec_later = _make_sample_record(src_addr="192.168.1.52", timestamp=str(base_ts + 15))
        matched, obs, thresh, _ = self.detector.evaluate_sliding_window_threshold(
            rec_later, threshold=5.0, window_seconds=10
        )
        assert matched is False
        assert obs == 1.0  # Only the new event remains in the 10-second window


# ===========================================================================
# A06: Rate and Ratio Analysis
# ===========================================================================

class TestA06RateAndRatioAnalysis:
    def setup_method(self):
        self.detector = ThresholdDetector()

    def test_a06_rate_exceeded(self):
        base_ts = 1700000000.0
        # 10 events over a 5 second window -> rate = 10 / 5 = 2.0 pps
        matched = False
        for i in range(10):
            rec = _make_sample_record(src_addr="10.0.0.1", timestamp=str(base_ts + i * 0.5))
            matched, obs_rate, thresh, ev = self.detector.evaluate_rate_and_ratio(
                record=rec,
                threshold=1.5,
                window_seconds=5,
                analysis_type="rate",
                group_by_field="source_address",
            )
        assert matched is True
        assert obs_rate >= 1.5

    def test_a06_ratio_analysis(self):
        base_ts = 1700000000.0
        # Send 10 total frames, 8 of which are Deauthentication (ratio 0.8)
        matched = False
        for i in range(10):
            st = "Deauthentication" if i < 8 else "Beacon"
            rec = _make_sample_record(
                src_addr="10.0.0.2",
                frame_subtype=st,
                timestamp=str(base_ts + i),
            )
            matched, obs_ratio, thresh, ev = self.detector.evaluate_rate_and_ratio(
                record=rec,
                threshold=0.75,
                window_seconds=60,
                analysis_type="ratio",
                target_condition_field="frame_subtype",
                target_condition_value="Deauthentication",
            )
        assert matched is True
        assert obs_ratio == 0.8
        assert ev["target_events"] == 8
        assert ev["total_events"] == 10


# ===========================================================================
# A07: Distinct Count and Cardinality Analysis
# ===========================================================================

class TestA07DistinctCountAnalysis:
    def setup_method(self):
        self.detector = ThresholdDetector()

    def test_a07_distinct_port_scan_detection(self):
        base_ts = 1700000000.0
        # Single source scanning 6 distinct ports with threshold=5
        matched = False
        for port in [21, 22, 23, 80, 443, 8080]:
            rec = _make_sample_record(
                src_addr="192.168.1.99",
                dst_port=port,
                timestamp=str(base_ts),
            )
            matched, distinct_count, thresh, ev = self.detector.evaluate_distinct_count(
                record=rec,
                target_field="dst_port",
                threshold=5.0,
                window_seconds=60,
                group_by_field="source_address",
            )
        assert matched is True
        assert distinct_count == 6.0
        assert thresh == 5.0
        assert len(ev["sample_distinct_values"]) == 6

    def test_a07_target_field_unavailable(self):
        rec = _make_sample_record()
        # Non-existent field
        matched, count, thresh, ev = self.detector.evaluate_distinct_count(
            record=rec, target_field="non_existent_field", threshold=5.0
        )
        assert matched is False
        assert "not available" in ev["reason"]


# ===========================================================================
# A08: Sequence and State-Based Detection
# ===========================================================================

class TestA08SequenceStateDetection:
    def setup_method(self):
        self.pattern_id = PatternIdentifier()

    def test_a08_valid_sequence_does_not_trigger(self):
        mac = "00:11:22:33:44:01"
        # Normal sequence: PROBE -> AUTH -> ASSOC -> DATA
        for subtype in ["Probe Request", "Authentication", "Association Request", "Data"]:
            rec = _make_sample_record(src_mac=mac, frame_subtype=subtype)
            matched, ev = self.pattern_id.evaluate_sequence_state(
                record=rec, group_by_field="source_mac", event_field="frame_subtype"
            )
            assert matched is False

    def test_a08_suspicious_transition_triggers(self):
        mac = "00:11:22:33:44:02"
        # Disallowed transition: START -> ASSOC without prior Auth
        rec = _make_sample_record(src_mac=mac, frame_subtype="Association Request")
        matched, ev = self.pattern_id.evaluate_sequence_state(
            record=rec, group_by_field="source_mac", event_field="frame_subtype"
        )
        assert matched is True
        assert "Disallowed state transition" in ev["violation_reason"]


# ===========================================================================
# A09: Baseline Deviation Detection
# ===========================================================================

class TestA09BaselineDeviationDetection:
    def setup_method(self):
        self.detector = StatisticalDetector()

    def test_a09_insufficient_baseline(self):
        rec = _make_sample_record(packet_length=100)
        matched, obs_z, thresh_z, ev = self.detector.evaluate_baseline_deviation(
            record=rec,
            metric_field="packet_length",
            threshold_z_score=3.0,
            min_baseline_samples=5,
        )
        assert matched is False
        assert "Insufficient baseline" in ev["reason"]

    def test_a09_baseline_normal_and_deviation(self):
        # Establish baseline around 100 bytes (e.g. 98, 102, 100, 99, 101)
        for val in [98, 102, 100, 99, 101]:
            rec = _make_sample_record(src_addr="10.10.10.1", packet_length=val)
            self.detector.evaluate_baseline_deviation(
                record=rec,
                metric_field="packet_length",
                threshold_z_score=3.0,
                min_baseline_samples=5,
                group_by_field="source_address",
            )

        # Normal packet (103 bytes) -> should NOT trigger
        rec_normal = _make_sample_record(src_addr="10.10.10.1", packet_length=103)
        matched_normal, z_norm, _, _ = self.detector.evaluate_baseline_deviation(
            record=rec_normal,
            metric_field="packet_length",
            threshold_z_score=3.0,
            min_baseline_samples=5,
            group_by_field="source_address",
        )
        assert matched_normal is False
        assert z_norm < 3.0

        # Anomalous massive packet (5000 bytes) -> should trigger deviation
        rec_anom = _make_sample_record(src_addr="10.10.10.1", packet_length=5000)
        matched_anom, z_anom, _, ev_anom = self.detector.evaluate_baseline_deviation(
            record=rec_anom,
            metric_field="packet_length",
            threshold_z_score=3.0,
            min_baseline_samples=5,
            group_by_field="source_address",
        )
        assert matched_anom is True
        assert z_anom >= 3.0
        assert ev_anom["matched"] is True


# ===========================================================================
# A10: Allowlist and Policy Comparison
# ===========================================================================

class TestA10AllowlistPolicyComparison:
    def setup_method(self):
        self.detector = SignatureDetector()

    def test_a10_approved_value_is_not_suspicious(self):
        rec = _make_sample_record(src_addr="192.168.1.100")
        allowlist = ["192.168.1.100", "192.168.1.101"]
        matched, ev = self.detector.evaluate_allowlist_policy(
            record=rec, field_to_check="source_address", allowlist=allowlist
        )
        assert matched is False
        assert ev["is_allowed"] is True

    def test_a10_unapproved_value_triggers_violation(self):
        rec = _make_sample_record(src_addr="10.99.99.99")
        allowlist = ["192.168.1.100", "192.168.1.101"]
        matched, ev = self.detector.evaluate_allowlist_policy(
            record=rec, field_to_check="source_address", allowlist=allowlist
        )
        assert matched is True
        assert ev["is_allowed"] is False

    def test_a10_missing_policy_is_benign(self):
        rec = _make_sample_record(src_addr="10.99.99.99")
        # Empty allowlist / missing policy
        matched, ev = self.detector.evaluate_allowlist_policy(
            record=rec, field_to_check="source_address", allowlist=None
        )
        assert matched is False
        assert "not defined" in ev["reason"]


# ===========================================================================
# A11: Multi-Condition Correlation
# ===========================================================================

class TestA11MultiConditionCorrelation:
    def setup_method(self):
        self.pattern_id = PatternIdentifier()

    def test_a11_and_correlation_match(self):
        rec = _make_sample_record(protocol="TCP", dst_port=80, packet_length=200)
        conds = [
            {"field": "protocol", "operator": "eq", "value": "TCP"},
            {"field": "dst_port", "operator": "eq", "value": 80},
            {"field": "packet_length", "operator": ">", "value": 100},
        ]
        matched, ev = self.pattern_id.evaluate_multi_condition_correlation(
            record=rec, conditions=conds, correlation_operator="AND"
        )
        assert matched is True
        assert ev["matched_conditions_count"] == 3

    def test_a11_and_correlation_non_match(self):
        rec = _make_sample_record(protocol="TCP", dst_port=443)
        conds = [
            {"field": "protocol", "operator": "eq", "value": "TCP"},
            {"field": "dst_port", "operator": "eq", "value": 80},  # Fails
        ]
        matched, ev = self.pattern_id.evaluate_multi_condition_correlation(
            record=rec, conditions=conds, correlation_operator="AND"
        )
        assert matched is False
        assert ev["matched_conditions_count"] == 1

    def test_a11_or_correlation_match(self):
        rec = _make_sample_record(protocol="UDP", dst_port=53)
        conds = [
            {"field": "protocol", "operator": "eq", "value": "TCP"},
            {"field": "dst_port", "operator": "eq", "value": 53},
        ]
        matched, ev = self.pattern_id.evaluate_multi_condition_correlation(
            record=rec, conditions=conds, correlation_operator="OR"
        )
        assert matched is True
