"""Integration tests for E2 Suspicious Pattern Detection Engine.

Validates end-to-end integration between E1, E2, E3, and E4:
- E1 ProcessedRecord / E1DetectionOutput accepted by E2
- E2 retrieves enabled rules through E3
- E2 stores matched results through E3
- E2 stores unmatched results through E3
- E2 forwards suspicious results to E4
- Normal records do not generate alerts
- UUID mapping is preserved
- Error handling on E3/E4 failures
- Batch resilience to malformed records
- Deterministic reproducibility and performance tracking
"""

import uuid
from typing import Any, Dict, List
import pytest
from unittest.mock import MagicMock
from sqlalchemy import BigInteger, create_engine, event
from sqlalchemy.dialects.postgresql import UUID as _PG_UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import Session, sessionmaker

from backend.src.database.base import Base
from backend.src.database.models import Detection_Rule, User
from backend.src.engines.e1_log_processing.log_processor import ProcessedRecord
from backend.src.engines.e1_log_processing.processing_pipeline import (
    E1DetectionOutput,
    ProcessingSummary,
)
from backend.src.common.constants import ProcessingStatus, ValidationStatus
from backend.src.engines.e2_suspicious_pattern_detection import (
    DetectionAlgorithm,
    DetectionEngine,
    DetectionRuleDefinition,
    SuspiciousPatternDetectionEngine,
)
from backend.src.engines.e3_log_alert_storage.alert_repository import AlertRepository
from backend.src.engines.e3_log_alert_storage.batch_repository import BatchRepository
from backend.src.engines.e3_log_alert_storage.log_repository import LogRepository
from backend.src.engines.e3_log_alert_storage.result_repository import ResultRepository
from backend.src.engines.e3_log_alert_storage.rule_repository import RuleRepository
from backend.src.engines.e3_log_alert_storage.storage_engine import StorageEngine
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.engines.e4_alert_generation.e4_engine import E4AlertEngine


# ---------------------------------------------------------------------------
# SQLite compatibility for testing
# ---------------------------------------------------------------------------

@compiles(_PG_UUID, "sqlite")
def _compile_pg_uuid_sqlite(type_, compiler, **kw):
    return "CHAR(36)"


@compiles(BigInteger, "sqlite")
def _compile_bigint_sqlite(type_, compiler, **kw):
    return "INTEGER"


def _make_sqlite_test_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )

    @event.listens_for(engine, "connect")
    def _fk_pragma(dbapi_con, _record):
        dbapi_con.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def sqlite_storage():
    """Provides a StorageEngine instance backed by SQLite for integration testing."""
    engine = _make_sqlite_test_engine()
    connection = engine.connect()
    trans = connection.begin()
    Session_ = sessionmaker(bind=connection)

    # Monkeypatch session factory for StorageEngine in test scope
    storage = StorageEngine()

    # We will use direct sessions to populate prerequisites (User, Log_Batch, Traffic_Log, Detection_Rule)
    yield storage, connection, Session_

    trans.rollback()
    connection.close()
    engine.dispose()


def _create_db_prerequisites(session: Session) -> Dict[str, Any]:
    """Sets up User, Log_Batch, Traffic_Logs, and Detection_Rules in database."""
    user_repo = UserRepository(session)
    user = user_repo.create(username=f"user_{uuid.uuid4().hex[:6]}", password_hash="hash", role="analyst")

    batch_repo = BatchRepository(session)
    batch_uuid = uuid.uuid4()
    batch = batch_repo.create(
        batch_uuid=batch_uuid,
        user_id=user.user_id,
        file_name="capture.pcap",
        file_format="pcap",
        processing_status="SUCCESS",
        total_records=2,
        processed_records=2,
    )

    log_repo = LogRepository(session)
    log1_uuid = uuid.uuid4()
    log1 = log_repo.create(
        log_uuid=log1_uuid,
        batch_id=batch.batch_id,
        source_address="192.168.1.100",
        destination_address="192.168.1.1",
        protocol="802.11_MGMT",
        log_details='{"wireless": {"frame_subtype": "Deauthentication"}}',
    )

    log2_uuid = uuid.uuid4()
    log2 = log_repo.create(
        log_uuid=log2_uuid,
        batch_id=batch.batch_id,
        source_address="192.168.1.105",
        destination_address="192.168.1.1",
        protocol="802.11_MGMT",
        log_details='{"wireless": {"frame_subtype": "Beacon"}}',
    )

    rule_repo = RuleRepository(session)
    rule1 = rule_repo.create(
        rule_name="Deauth_Flood_Rule",
        suspicious_activity="Deauthentication Flood Attack",
        protocol="802.11_MGMT",
        detection_condition='{"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}',
        severity="CRITICAL",
        is_enabled=True,
    )

    session.commit()

    return {
        "user": user,
        "batch": batch,
        "log1": log1,
        "log1_uuid": str(log1_uuid),
        "log2": log2,
        "log2_uuid": str(log2_uuid),
        "rule1": rule1,
    }


class TestE2EngineIntegration:
    """End-to-end integration tests connecting E1 outputs, E2 detection, E3 storage, and E4 alerts."""

    def test_e1_to_e2_processed_records_acceptance(self):
        """E1 ProcessedRecords and E1DetectionOutput are accepted and processed by E2."""
        engine = SuspiciousPatternDetectionEngine()
        log_uuid = str(uuid.uuid4())
        rec = ProcessedRecord(
            log_id=log_uuid,
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80, "packet_length": 64},
        )

        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="HTTP_Traffic",
            suspicious_activity="HTTP Inspection",
            protocol="TCP",
            detection_condition="dst_port == 80",
            severity="LOW",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 80},
        )

        # 1. Direct record evaluation
        outcomes = engine.process_record(rec, rules=[rule], persist_results=False, forward_alerts=False)
        assert len(outcomes) == 1
        assert outcomes[0].log_uuid == log_uuid
        assert outcomes[0].rule_match_status is True

        # 2. Batch input via E1DetectionOutput
        summary = ProcessingSummary(
            batch_id=rec.batch_id,
            file_name="test.pcap",
            file_format="pcap",
            file_size_bytes=1024,
            total_packets_encountered=1,
            successfully_processed_packets=1,
            failed_packets=0,
            skipped_packets=0,
            processing_start_time="2026-11-12T17:00:00Z",
            processing_completion_time="2026-11-12T17:00:01Z",
            duration_seconds=1.0,
            packets_per_second=1.0,
            processing_status=ProcessingStatus.SUCCESS,
            validation_status=ValidationStatus.VALID,
        )
        e1_output = E1DetectionOutput(
            batch_id=rec.batch_id,
            records=[rec],
            summary=summary,
        )

        batch_res = engine.process_batch(
            e1_output, rules=[rule], persist_results=False, forward_alerts=False
        )
        assert batch_res.total_records == 1
        assert len(batch_res.matched_outcomes) == 1
        assert batch_res.metrics.records_processed == 1

    def test_e2_stores_matched_and_unmatched_results_in_e3(self):
        """E2 persists BOTH matched and unmatched detection results through E3."""
        mock_e3 = MagicMock()
        mock_e3.store_detection_result.return_value = {"result_id": 101, "skipped": False}
        mock_e3.get_enabled_rules.return_value = [
            {
                "rule_id": 1,
                "rule_name": "Deauth_Match_Rule",
                "suspicious_activity": "Deauth Flood",
                "protocol": "802.11_MGMT",
                "detection_condition": '{"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}',
                "severity": "CRITICAL",
                "is_enabled": True,
            }
        ]

        engine = SuspiciousPatternDetectionEngine(storage_engine=mock_e3)

        # Record 1: Matched (Deauthentication)
        log1_uuid = str(uuid.uuid4())
        rec1 = ProcessedRecord(
            log_id=log1_uuid,
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="802.11_MGMT",
            log_details={"wireless": {"frame_subtype": "Deauthentication"}},
        )

        # Record 2: Unmatched (Beacon)
        log2_uuid = str(uuid.uuid4())
        rec2 = ProcessedRecord(
            log_id=log2_uuid,
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:01+00:00",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="802.11_MGMT",
            log_details={"wireless": {"frame_subtype": "Beacon"}},
        )

        batch_res = engine.process_batch([rec1, rec2], persist_results=True, forward_alerts=False)

        assert batch_res.total_records == 2
        assert len(batch_res.matched_outcomes) == 1
        assert len(batch_res.unmatched_outcomes) == 1

        # Check E3 store_detection_result was called for BOTH matched and unmatched
        assert mock_e3.store_detection_result.call_count == 2
        calls = mock_e3.store_detection_result.call_args_list

        # Call 1 should be matched=True
        call1_kwargs = calls[0].kwargs
        assert call1_kwargs["log_uuid"] == log1_uuid
        assert call1_kwargs["rule_match_status"] is True

        # Call 2 should be matched=False
        call2_kwargs = calls[1].kwargs
        assert call2_kwargs["log_uuid"] == log2_uuid
        assert call2_kwargs["rule_match_status"] is False

    def test_e2_forwards_only_suspicious_results_to_e4(self):
        """E2 forwards suspicious results to E4; normal results generate NO alerts."""
        mock_e4 = MagicMock()
        mock_e4.process_result.return_value = (MagicMock(), None)

        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="Deauth_Detection",
            suspicious_activity="Deauth Flood",
            protocol="802.11_MGMT",
            detection_condition='{"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"}',
            severity="CRITICAL",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "frame_subtype", "operator": "eq", "value": "Deauthentication"},
        )

        engine = SuspiciousPatternDetectionEngine(alert_engine=mock_e4)

        # Suspicious record
        rec_suspicious = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="802.11_MGMT",
            log_details={"wireless": {"frame_subtype": "Deauthentication"}},
        )

        # Normal record
        rec_normal = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:01+00:00",
            source_address="192.168.1.100",
            destination_address="192.168.1.1",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="802.11_MGMT",
            log_details={"wireless": {"frame_subtype": "Beacon"}},
        )

        batch_res = engine.process_batch(
            [rec_suspicious, rec_normal], rules=[rule], persist_results=False, forward_alerts=True
        )

        assert batch_res.metrics.matched_results_count == 1
        assert batch_res.metrics.unmatched_results_count == 1

        # Only 1 alert was forwarded to E4 (the suspicious one)
        assert mock_e4.process_result.call_count == 1
        forwarded_payload = mock_e4.process_result.call_args[0][0]
        assert forwarded_payload["rule_match_status"] is True
        assert forwarded_payload["log_id"] == rec_suspicious.log_id
        # result_id in payload matches result_uuid
        assert forwarded_payload["result_id"] == batch_res.matched_outcomes[0].result_uuid

    def test_uuid_mapping_preserved(self):
        """External log UUID from E1 and new result UUID from E2 are preserved end-to-end."""
        engine = SuspiciousPatternDetectionEngine()
        log_uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        rec = ProcessedRecord(
            log_id=log_uuid,
            batch_id="bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )
        rule = DetectionRuleDefinition(
            rule_id=99,
            rule_name="R99",
            suspicious_activity="Activity",
            protocol="TCP",
            detection_condition="dst_port == 80",
            severity="MEDIUM",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 80},
        )

        outcome = engine.evaluate_record_against_rule(rec, rule)
        # Verify result_uuid is valid UUID string and log_uuid is preserved exactly
        assert uuid.UUID(outcome.result_uuid)  # Should not raise
        assert outcome.log_uuid == log_uuid
        assert isinstance(outcome.log_uuid, str)
        assert outcome.rule_id == 99

        # Verify e3 kwargs
        e3_dict = outcome.to_e3_kwargs()
        assert e3_dict["result_uuid"] == outcome.result_uuid
        assert e3_dict["log_uuid"] == log_uuid

        # Verify e4 payload
        e4_payload = outcome.to_e4_payload()
        assert e4_payload["result_id"] == outcome.result_uuid
        assert e4_payload["log_id"] == log_uuid

    def test_e3_before_e4_sequencing_and_failure_handling(self):
        """Validates strict E3-before-E4 sequencing across matched, unmatched, and failing E3 writes."""
        mock_e3 = MagicMock()
        mock_e4 = MagicMock()
        mock_e4.process_result.return_value = (MagicMock(), None)

        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="R1",
            suspicious_activity="Act",
            protocol="TCP",
            detection_condition="dst_port == 80",
            severity="HIGH",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 80},
        )

        engine = SuspiciousPatternDetectionEngine(
            storage_engine=mock_e3, alert_engine=mock_e4
        )

        # Record 1: Matched (port 80)
        rec_matched = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        # Record 2: Unmatched (port 443)
        rec_unmatched = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:01+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 443},
        )

        # Record 3: Matched (port 80) but will simulate E3 write failure
        rec_matched_fail = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:02+00:00",
            source_address="10.0.0.3",
            destination_address="10.0.0.4",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        # Record 4: Matched (port 80) after failure to verify subsequent processing continues
        rec_matched_subsequent = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:03+00:00",
            source_address="10.0.0.5",
            destination_address="10.0.0.6",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        # Configure mock_e3:
        # call 1 (rec_matched): success
        # call 2 (rec_unmatched): success
        # call 3 (rec_matched_fail): raises RuntimeError
        # call 4 (rec_matched_subsequent): success
        mock_e3.store_detection_result.side_effect = [
            {"result_id": 1, "skipped": False},
            {"result_id": 2, "skipped": False},
            RuntimeError("Simulated E3 disk/database failure"),
            {"result_id": 3, "skipped": False},
        ]

        batch_res = engine.process_batch(
            [rec_matched, rec_unmatched, rec_matched_fail, rec_matched_subsequent],
            rules=[rule],
            persist_results=True,
            forward_alerts=True,
        )

        # 1. Total records and rules processed
        assert batch_res.metrics.records_processed == 4
        assert batch_res.metrics.rules_evaluated_count == 4
        assert batch_res.metrics.matched_results_count == 3
        assert batch_res.metrics.unmatched_results_count == 1

        # 2. E3 persistence attempted for all 4
        assert mock_e3.store_detection_result.call_count == 4
        assert batch_res.metrics.results_stored_e3 == 3
        assert batch_res.metrics.e3_storage_failures == 1

        # 3. Check E4 forwarding calls:
        # - rec_matched: matched + E3 success -> forwarded (1)
        # - rec_unmatched: unmatched + E3 success -> stored but NOT forwarded (0)
        # - rec_matched_fail: matched + E3 failure -> NOT forwarded (0)
        # - rec_matched_subsequent: matched + E3 success -> forwarded (1)
        # Total forwarded to E4 must be exactly 2
        assert mock_e4.process_result.call_count == 2
        assert batch_res.metrics.alerts_forwarded_e4 == 2

        forwarded_log_ids = [
            call[0][0]["log_id"] for call in mock_e4.process_result.call_args_list
        ]
        assert rec_matched.log_id in forwarded_log_ids
        assert rec_matched_subsequent.log_id in forwarded_log_ids
        assert rec_unmatched.log_id not in forwarded_log_ids
        assert rec_matched_fail.log_id not in forwarded_log_ids

    def test_e4_communication_failure_metric_tracked(self):
        """E4 communication errors do not stop processing and increment e4_forward_failures."""
        mock_e3 = MagicMock()
        mock_e3.store_detection_result.return_value = {"result_id": 1, "skipped": False}

        failing_e4 = MagicMock()
        failing_e4.process_result.side_effect = ConnectionError("E4 Dispatch Error")

        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="R1",
            suspicious_activity="Act",
            protocol="TCP",
            detection_condition="dst_port == 80",
            severity="HIGH",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 80},
        )

        engine = SuspiciousPatternDetectionEngine(
            storage_engine=mock_e3, alert_engine=failing_e4
        )

        rec = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        batch_res = engine.process_batch([rec], rules=[rule], persist_results=True, forward_alerts=True)
        assert batch_res.metrics.records_processed == 1
        assert batch_res.metrics.results_stored_e3 == 1
        assert batch_res.metrics.e3_storage_failures == 0
        assert batch_res.metrics.e4_forward_failures == 1

    def test_batch_resilience_to_malformed_records(self):
        """Batch continues processing valid records when encountering malformed records."""
        engine = SuspiciousPatternDetectionEngine()
        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="R1",
            suspicious_activity="Act",
            protocol="TCP",
            detection_condition="dst_port == 80",
            severity="HIGH",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 80},
        )

        valid_rec1 = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:00+00:00",
            source_address="10.0.0.1",
            destination_address="10.0.0.2",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        # Malformed record: missing log_id
        malformed_rec = {"source_address": "10.0.0.5", "protocol": "TCP"}

        valid_rec2 = ProcessedRecord(
            log_id=str(uuid.uuid4()),
            batch_id=str(uuid.uuid4()),
            timestamp="2026-11-12T17:00:02+00:00",
            source_address="10.0.0.3",
            destination_address="10.0.0.4",
            source_mac="00:11:22:33:44:55",
            destination_mac="66:77:88:99:aa:bb",
            protocol="TCP",
            log_details={"destination_port": 80},
        )

        batch_res = engine.process_batch(
            [valid_rec1, malformed_rec, valid_rec2],
            rules=[rule],
            persist_results=False,
            forward_alerts=False,
        )

        assert batch_res.total_records == 3
        assert batch_res.metrics.records_processed == 2
        assert batch_res.metrics.records_invalid == 1
        assert len(batch_res.outcomes) == 2

    def test_reproducibility_and_performance_metrics(self):
        """Repeated identical input produces identical detection decisions and measures performance."""
        engine = SuspiciousPatternDetectionEngine()
        rule = DetectionRuleDefinition(
            rule_id=1,
            rule_name="R1",
            suspicious_activity="Act",
            protocol="TCP",
            detection_condition="dst_port == 443",
            severity="HIGH",
            algorithm=DetectionAlgorithm.A04_PATTERN_MATCHING,
            parsed_condition={"field": "dst_port", "operator": "==", "value": 443},
        )

        records = [
            ProcessedRecord(
                log_id=str(uuid.uuid4()),
                batch_id="batch_perf",
                timestamp="2026-11-12T17:00:00+00:00",
                source_address=f"10.0.0.{i % 254 + 1}",
                destination_address="10.0.0.254",
                source_mac="00:11:22:33:44:55",
                destination_mac="66:77:88:99:aa:bb",
                protocol="TCP",
                log_details={"destination_port": 443 if i % 2 == 0 else 80},
            )
            for i in range(100)
        ]

        # Run 1
        res1 = engine.process_batch(records, rules=[rule], persist_results=False, forward_alerts=False)
        # Run 2
        res2 = engine.process_batch(records, rules=[rule], persist_results=False, forward_alerts=False)

        assert res1.metrics.records_processed == res2.metrics.records_processed == 100
        assert res1.metrics.matched_results_count == res2.metrics.matched_results_count == 50
        assert res1.metrics.unmatched_results_count == res2.metrics.unmatched_results_count == 50

        # Performance metrics are measured
        assert res1.metrics.duration_seconds > 0
        assert res1.metrics.records_per_second > 0
        assert res1.metrics.evaluations_per_second > 0

        # Unique UUID check
        uuids = {o.result_uuid for o in res1.outcomes}
        assert len(uuids) == 100  # Every result has a distinct UUID
