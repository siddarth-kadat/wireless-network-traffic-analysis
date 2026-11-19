"""Integration tests for EngineCoordinator, MessageHandler, and PipelineController."""

import time
from pathlib import Path
import pytest

from backend.src.coordination.engine_coordinator import EngineCoordinator, resolve_user_id
from backend.src.coordination.message_handler import CoordinationEvent, EventType, MessageHandler
from backend.src.coordination.pipeline_controller import JobStatus, PipelineController
from backend.src.database.connection import SessionLocal
from backend.src.database.initialization import init_database
from backend.src.database.models import Detection_Result, Log_Batch, Traffic_Log


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure database tables and initial rules exist."""
    init_database()


def test_message_handler_pub_sub():
    """Test publish/subscribe and event tracking in MessageHandler."""
    handler = MessageHandler()
    received_events = []

    def on_event(evt: CoordinationEvent):
        received_events.append(evt)

    handler.subscribe(EventType.PCAP_INGESTION_STARTED, on_event)
    handler.publish(
        EventType.PCAP_INGESTION_STARTED,
        batch_id="test-batch-001",
        payload={"packets": 10},
        message="Started test",
    )

    assert len(received_events) == 1
    assert received_events[0].batch_id == "test-batch-001"
    assert received_events[0].event_type == EventType.PCAP_INGESTION_STARTED

    # Test history retrieval
    history = handler.get_history(batch_id="test-batch-001")
    assert len(history) == 1
    assert history[0].batch_id == "test-batch-001"

    # Test unsubscribe
    handler.unsubscribe(EventType.PCAP_INGESTION_STARTED, on_event)
    handler.publish(EventType.PCAP_INGESTION_STARTED, batch_id="test-batch-002")
    assert len(received_events) == 1  # No new event received


def test_resolve_user_id():
    """Test user identifier resolution."""
    assert resolve_user_id(42) == 42
    assert resolve_user_id("7") == 7
    # Resolves 'admin' to integer ID (usually 1)
    admin_id = resolve_user_id("admin")
    assert isinstance(admin_id, int)
    assert admin_id > 0


def test_engine_coordinator_process_pcap(valid_wireless_pcap: Path):
    """Test end-to-end execution of EngineCoordinator with wireless capture."""
    coordinator = EngineCoordinator()
    summary = coordinator.process_pcap_file(valid_wireless_pcap, user_id=1)

    assert summary["processing_status"] == "SUCCESS"
    assert summary["total_records"] == 1
    assert summary["logs_stored"] == 1
    assert summary["batch_id"] > 0
    assert summary["duration_seconds"] > 0

    # Verify database persistence across all tables
    with SessionLocal() as session:
        batch = session.get(Log_Batch, summary["batch_id"])
        assert batch is not None
        assert batch.file_name == "valid_wireless.pcap"

        logs = session.query(Traffic_Log).filter(Traffic_Log.batch_id == summary["batch_id"]).all()
        assert len(logs) == 1
        assert logs[0].protocol == "802.11_MGMT"


def test_pipeline_controller_async_job(valid_wireless_pcap: Path):
    """Test asynchronous task execution with PipelineController."""
    controller = PipelineController()
    job_id = controller.submit_job(valid_wireless_pcap, user_id=1)

    assert job_id.startswith("job-")

    # Wait for completion (up to 5 seconds)
    completed = False
    for _ in range(50):
        job = controller.get_job(job_id)
        if job and job["status"] in (JobStatus.COMPLETED.value, JobStatus.FAILED.value):
            completed = True
            break
        time.sleep(0.1)

    assert completed
    final_job = controller.get_job(job_id)
    assert final_job["status"] == JobStatus.COMPLETED.value
    assert final_job["progress"] == 100
    assert final_job["result"] is not None
    assert final_job["result"]["logs_stored"] == 1
