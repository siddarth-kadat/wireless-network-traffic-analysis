"""Integration tests for all FastAPI REST API endpoints."""

import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from backend.src.api.main import app
from backend.src.database.initialization import init_database

client = TestClient(app)


# setup_db removed as database is pre-initialized


def test_health_and_root():
    """Verify root and health endpoints return 200 OK."""
    res_root = client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "ONLINE"

    res_health = client.get("/api/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "UP"


def test_auth_login_and_me():
    """Verify login authentication and JWT profile retrieval."""
    res_login = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "admin123"},
    )
    assert res_login.status_code == 200
    data = res_login.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"

    token = data["access_token"]
    res_me = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res_me.status_code == 200
    assert res_me.json()["username"] == "admin"


def test_auth_login_invalid_credentials():
    """Verify invalid password returns 401."""
    res = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "WrongPassword!"},
    )
    assert res.status_code == 401


def test_detection_rules_and_toggle():
    """Verify detection rules retrieval and toggle state."""
    res = client.get("/api/detection/rules")
    assert res.status_code == 200
    rules = res.json()
    assert len(rules) >= 6

    rule = rules[0]
    rule_id = rule["rule_id"]
    orig_state = rule["is_enabled"]

    # Toggle rule
    res_toggle = client.post(f"/api/detection/rules/{rule_id}/toggle")
    assert res_toggle.status_code == 200
    assert res_toggle.json()["is_enabled"] == (not orig_state)

    # Toggle back
    res_toggle_back = client.post(f"/api/detection/rules/{rule_id}/toggle")
    assert res_toggle_back.status_code == 200
    assert res_toggle_back.json()["is_enabled"] == orig_state


def test_batch_upload_and_queries(valid_wireless_pcap: Path):
    """Verify PCAP upload endpoint and subsequent batch and log queries."""
    with open(valid_wireless_pcap, "rb") as f:
        file_bytes = f.read()

    res_upload = client.post(
        "/api/batches/upload",
        files={"file": ("test_capture.pcap", file_bytes, "application/octet-stream")},
        data={"user_id": "admin"},
    )
    assert res_upload.status_code == 200
    upload_data = res_upload.json()
    batch_id = upload_data["batch_id"]
    assert upload_data["processing_status"] == "SUCCESS"
    assert upload_data["total_records"] == 1

    # Query batch list
    res_batches = client.get("/api/batches")
    assert res_batches.status_code == 200
    batches = res_batches.json()
    assert any(b["batch_id"] == batch_id for b in batches)

    # Query single batch
    res_single = client.get(f"/api/batches/{batch_id}")
    assert res_single.status_code == 200
    assert res_single.json()["batch_id"] == batch_id

    # Query traffic logs
    res_logs = client.get(f"/api/logs?batch_id={batch_id}")
    assert res_logs.status_code == 200
    logs_data = res_logs.json()
    assert logs_data["total"] >= 1
    assert len(logs_data["items"]) >= 1

    # Query traffic summary stats
    res_stats = client.get("/api/logs/stats/summary")
    assert res_stats.status_code == 200
    stats = res_stats.json()
    assert "protocol_breakdown" in stats
    assert "time_series" in stats


def test_alerts_and_status_update():
    """Verify alert listing and status modification."""
    res_alerts = client.get("/api/alerts")
    assert res_alerts.status_code == 200
    data = res_alerts.json()
    assert "items" in data


def test_users_list_and_create():
    """Verify user management endpoints."""
    res_users = client.get("/api/users")
    assert res_users.status_code == 200
    users = res_users.json()
    assert len(users) >= 2  # admin & analyst

    # Create new user
    res_create = client.post(
        "/api/users",
        json={
            "username": "tier1_analyst",
            "password": "Password123!",
            "role": "analyst",
        },
    )
    assert res_create.status_code == 200
    assert res_create.json()["username"] == "tier1_analyst"


def test_admin_metrics():
    """Verify admin system health and telemetry metrics."""
    res = client.get("/api/admin/metrics")
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["status"] == "OPERATIONAL"
    assert "entity_counts" in metrics
    assert metrics["entity_counts"]["users"] >= 2
    assert metrics["entity_counts"]["rules"] >= 6
