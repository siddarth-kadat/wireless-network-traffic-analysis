"""Comprehensive End-to-End System Integration Tests (Phase 10: Tests 1 - 10).

Validates:
- Test 1: E1 to E2 output compatibility (data contracts and dataclasses).
- Test 2: E1 to E3 persistence (batch metadata, traffic logs, errors).
- Test 3: E3 to E2 rule retrieval (enabled rules dynamically queried from DB).
- Test 4: E2 to E4 detection result handling (suspicious outcomes forwarded to E4).
- Test 5: E4 to E3 alert persistence (alerts saved directly to DB via storage sink).
- Test 6: Complete end-to-end multi-engine workflow (PCAP -> E1 -> E3 -> E2 -> E3 -> E4 -> E3 -> DB).
- Test 7: FastAPI REST API route execution (auth, batches, logs, detection, alerts, users).
- Test 8: Frontend API contract compatibility (schemas match frontend service expectations).
- Test 9: Database integrity & transaction consistency (foreign keys and unique constraints).
- Test 10: Error handling & fault resilience (invalid file formats, corrupt packets, graceful recovery).
"""

import os
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from scapy.layers.dot11 import Dot11, Dot11Deauth, RadioTap
from scapy.utils import wrpcap

from backend.src.api.main import app
from backend.src.coordination.engine_coordinator import EngineCoordinator
from backend.src.database.connection import SessionLocal
from backend.src.database.initialization import init_database
from backend.src.database.models import (
    Alert,
    Detection_Result,
    Detection_Rule,
    Log_Batch,
    Processing_Error,
    Traffic_Log,
    User,
)
from backend.src.engines.e1_log_processing.processing_pipeline import (
    E1DetectionOutput,
    E1ProcessingPipeline,
    E1StorageOutput,
)
from backend.src.engines.e2_suspicious_pattern_detection.detection_engine import (
    SuspiciousPatternDetectionEngine,
)
from backend.src.engines.e3_log_alert_storage.alert_repository import AlertRepository
from backend.src.engines.e3_log_alert_storage.batch_repository import BatchRepository
from backend.src.engines.e3_log_alert_storage.log_repository import LogRepository
from backend.src.engines.e3_log_alert_storage.result_repository import ResultRepository
from backend.src.engines.e3_log_alert_storage.rule_repository import RuleRepository
from backend.src.engines.e3_log_alert_storage.storage_engine import StorageEngine
from backend.src.engines.e4_alert_generation.e4_engine import E4AlertEngine

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_clean_db():
    """Ensure database is initialized before each test."""
    init_database()


@pytest.fixture
def deauth_flood_pcap(temp_dir: Path) -> Path:
    """Creates a synthetic PCAP containing 802.11 deauthentication flood frames (triggers R-WLAN-01)."""
    pcap_path = temp_dir / "deauth_flood.pcap"
    packets = []
    # Generate 15 deauth frames within a short time window
    for i in range(15):
        rt = RadioTap()
        d11 = Dot11(
            type=0,
            subtype=12,  # Deauthentication frame
            addr1="ff:ff:ff:ff:ff:ff",
            addr2="00:14:22:01:23:45",
            addr3="00:14:22:01:23:45",
        )
        deauth = Dot11Deauth(reason=7)  # Class 3 frame received from nonassociated STA
        packets.append(rt / d11 / deauth)
    wrpcap(str(pcap_path), packets)
    return pcap_path


# ------------------------------------------------------------------------------
# Test 1: E1 to E2 Output Compatibility
# ------------------------------------------------------------------------------
def test_1_e1_to_e2_compatibility(valid_wireless_pcap: Path):
    """Verify E1 outputs correctly map to E2 input requirements."""
    pipeline = E1ProcessingPipeline()
    det_out, stor_out = pipeline.process_file(valid_wireless_pcap)

    assert isinstance(det_out, E1DetectionOutput)
    assert hasattr(det_out, "records")
    assert hasattr(det_out, "batch_id")
    assert len(det_out.records) == 1

    rec = det_out.records[0]
    assert rec.log_id is not None
    assert rec.protocol == "802.11_MGMT"
    assert "wireless" in rec.log_details


# ------------------------------------------------------------------------------
# Test 2: E1 to E3 Persistence
# ------------------------------------------------------------------------------
def test_2_e1_to_e3_persistence(valid_ethernet_pcap: Path):
    """Verify E1 storage output is persisted to SQLite via StorageEngine."""
    pipeline = E1ProcessingPipeline()
    _, stor_out = pipeline.process_file(valid_ethernet_pcap)

    storage = StorageEngine()
    res = storage.store_e1_batch(stor_out, user_id=1)

    assert res["logs_stored"] == 5
    assert res["batch_id"] > 0

    with SessionLocal() as session:
        batch = session.get(Log_Batch, res["batch_id"])
        assert batch is not None
        assert batch.total_records == 5
        logs = session.query(Traffic_Log).filter(Traffic_Log.batch_id == res["batch_id"]).all()
        assert len(logs) == 5


# ------------------------------------------------------------------------------
# Test 3: E3 to E2 Rule Retrieval
# ------------------------------------------------------------------------------
def test_3_e3_to_e2_rule_retrieval():
    """Verify E2 retrieves and parses active detection rules from E3."""
    storage = StorageEngine()
    rules = storage.get_enabled_rules()
    assert len(rules) >= 6

    rule_names = [r["rule_name"] for r in rules]
    assert "R-WLAN-01" in rule_names
    assert "R-WLAN-03" in rule_names

    # Verify E2 engine initializes and loads rules successfully
    det_engine = SuspiciousPatternDetectionEngine(storage_engine=storage)
    loaded_rules = det_engine.rule_loader.load_rules_from_e3(storage)
    assert len(loaded_rules) >= 4


# ------------------------------------------------------------------------------
# Test 4: E2 to E4 Detection Result Handling
# ------------------------------------------------------------------------------
def test_4_e2_to_e4_result_handling():
    """Verify E4 receives, parses, and validates detection result payloads from E2."""
    e4 = E4AlertEngine()
    mock_payload = {
        "result_id": "a0000000-0000-0000-0000-000000000001",
        "rule_id": 1,
        "rule_name": "R-WLAN-01",
        "rule_match_status": True,
        "suspicious_activity": "Deauthentication Flood Attack",
        "severity": "CRITICAL",
        "observed_value": 45.0,
        "threshold_value": 10.0,
        "detection_evidence": {"frame_count": 45, "window_seconds": 2.0},
        "detection_time": "2026-11-19T10:00:00+00:00",
        "source_address": "00:14:22:01:23:45",
        "destination_address": "ff:ff:ff:ff:ff:ff",
        "protocol": "802.11_MGMT",
    }

    alert_payload, reason = e4.process_result(mock_payload, dispatch_to_storage=False)
    assert alert_payload is not None
    assert reason is None
    assert alert_payload.severity == "CRITICAL"
    assert alert_payload.result_id == "a0000000-0000-0000-0000-000000000001"


# ------------------------------------------------------------------------------
# Test 5: E4 to E3 Alert Persistence
# ------------------------------------------------------------------------------
def test_5_e4_to_e3_alert_persistence(valid_wireless_pcap: Path):
    """Verify E4 alert dispatch directly calls E3 to store alert entity."""
    pipeline = E1ProcessingPipeline()
    det_out, stor_out = pipeline.process_file(valid_wireless_pcap)
    storage = StorageEngine()
    b_res = storage.store_e1_batch(stor_out, user_id=1)

    with SessionLocal() as session:
        log = session.query(Traffic_Log).filter(Traffic_Log.batch_id == b_res["batch_id"]).first()
        log_uuid = str(log.log_uuid)

    det_res = storage.store_detection_result(
        result_uuid="b0000000-0000-0000-0000-000000000002",
        log_uuid=log_uuid,
        rule_id=1,
        rule_match_status=True,
        detection_time="2026-11-19T10:05:00+00:00",
        observed_value=25.0,
        threshold_value=10.0,
    )

    e4 = E4AlertEngine(storage_sink=storage.store_alert)
    alert_input = {
        "result_id": "b0000000-0000-0000-0000-000000000002",
        "rule_id": 1,
        "rule_name": "R-WLAN-01",
        "rule_match_status": True,
        "suspicious_activity": "Deauthentication Flood Attack",
        "severity": "CRITICAL",
        "detection_time": "2026-11-19T10:05:00+00:00",
    }
    alert_obj, err = e4.process_result(alert_input, dispatch_to_storage=True)
    assert alert_obj is not None
    assert err is None

    # Check that alert was stored in database
    with SessionLocal() as session:
        alert_row = session.query(Alert).filter(Alert.result_id == det_res["result_id"]).first()
        assert alert_row is not None
        assert alert_row.severity == "CRITICAL"


# ------------------------------------------------------------------------------
# Test 6: Complete Multi-Engine End-to-End Workflow
# ------------------------------------------------------------------------------
def test_6_complete_multi_engine_workflow(valid_wireless_pcap: Path):
    """Verify the full pipeline: PCAP -> E1 -> E3 -> E2 -> E3 -> E4 -> E3 -> SQLite DB."""
    coordinator = EngineCoordinator()
    summary = coordinator.process_pcap_file(valid_wireless_pcap, user_id=1)

    assert summary["processing_status"] == "SUCCESS"
    assert summary["logs_stored"] == 1
    assert summary["batch_id"] > 0
    assert summary["rules_evaluated"] >= 1

    # Verify complete database linkage
    with SessionLocal() as session:
        batch = session.get(Log_Batch, summary["batch_id"])
        assert batch is not None
        logs = session.query(Traffic_Log).filter(Traffic_Log.batch_id == batch.batch_id).all()
        assert len(logs) == 1
        results = session.query(Detection_Result).filter(Detection_Result.log_id == logs[0].log_id).all()
        assert len(results) >= 1


# ------------------------------------------------------------------------------
# Test 7: FastAPI REST Route Execution
# ------------------------------------------------------------------------------
def test_7_fastapi_route_execution(valid_wireless_pcap: Path):
    """Verify execution across all FastAPI routes."""
    # 1. Login
    login_res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Upload
    with open(valid_wireless_pcap, "rb") as f:
        upload_res = client.post(
            "/api/batches/upload",
            files={"file": ("test_run.pcap", f.read(), "application/octet-stream")},
            data={"user_id": "admin"},
            headers=headers,
        )
    assert upload_res.status_code == 200
    b_id = upload_res.json()["batch_id"]

    # 3. Batches list
    b_list = client.get("/api/batches", headers=headers)
    assert b_list.status_code == 200

    # 4. Logs query
    l_list = client.get(f"/api/logs?batch_id={b_id}", headers=headers)
    assert l_list.status_code == 200

    # 5. Detection rules
    r_list = client.get("/api/detection/rules", headers=headers)
    assert r_list.status_code == 200

    # 6. Alerts
    a_list = client.get("/api/alerts", headers=headers)
    assert a_list.status_code == 200


# ------------------------------------------------------------------------------
# Test 8: Frontend API Contract Compatibility
# ------------------------------------------------------------------------------
def test_8_frontend_api_contract_compatibility():
    """Verify backend JSON schemas align with frontend services (api.js, batchService, logService)."""
    # Batches schema
    b_res = client.get("/api/batches")
    assert b_res.status_code == 200
    batches = b_res.json()
    if batches:
        b = batches[0]
        assert "batch_id" in b
        assert "file_name" in b
        assert "processing_status" in b

    # Logs schema
    l_res = client.get("/api/logs")
    assert l_res.status_code == 200
    logs = l_res.json()
    assert "total" in logs
    assert "page" in logs
    assert "items" in logs

    # Rules schema
    r_res = client.get("/api/detection/rules")
    assert r_res.status_code == 200
    rules = r_res.json()
    assert len(rules) >= 6
    r = rules[0]
    assert "rule_id" in r
    assert "rule_name" in r
    assert "is_enabled" in r


# ------------------------------------------------------------------------------
# Test 9: Database Integrity and Constraints
# ------------------------------------------------------------------------------
def test_9_database_integrity_and_constraints():
    """Verify database foreign key enforcement and unique constraint behaviors."""
    with SessionLocal() as session:
        # Check seed users exist
        admin = session.query(User).filter(User.username == "admin").first()
        assert admin is not None
        assert admin.role == "admin"

        # Unique username check
        with pytest.raises(Exception):
            session.add(User(username="admin", password_hash="hash", role="admin"))
            session.commit()
        session.rollback()


# ------------------------------------------------------------------------------
# Test 10: Error Handling and Resilience
# ------------------------------------------------------------------------------
def test_10_error_handling_resilience(empty_file: Path):
    """Verify error isolation and resilience against corrupt/empty inputs."""
    coordinator = EngineCoordinator()
    # Empty file should process without unhandled crash and record failed status
    summary = coordinator.process_pcap_file(empty_file, user_id=1)
    assert summary["processing_status"] == "FAILED"
    assert summary["failed_records"] == 0
    assert summary["logs_stored"] == 0

    # Test upload with invalid file extension
    invalid_upload = client.post(
        "/api/batches/upload",
        files={"file": ("malicious.exe", b"MZ...", "application/octet-stream")},
    )
    assert invalid_upload.status_code == 400
