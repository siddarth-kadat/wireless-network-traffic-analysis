"""Database schema creation and seed data initialization."""

import json
from sqlalchemy.orm import Session
from backend.src.common.logger import get_logger
from backend.src.database.base import Base
from backend.src.database.connection import SessionLocal, engine, init_engine
from backend.src.database.models import User, Detection_Rule
from backend.src.engines.e3_log_alert_storage.rule_repository import RuleRepository
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.security.password_hashing import hash_password

logger = get_logger(__name__)

INITIAL_USERS = [
    {
        "username": "admin",
        "password": "admin123",
        "role": "Network Administrator",
    },
    {
        "username": "analyst",
        "password": "analyst123",
        "role": "Security Analyst",
    },
]

INITIAL_RULES = [
    {
        "rule_name": "R-WLAN-01 (Deauth Flood Anomaly)",
        "suspicious_activity": "802.11 Deauth Broadcast Flood",
        "protocol": "802.11",
        "detection_condition": json.dumps({
            "target_field": "frame_subtype",
            "match_value": 12,
            "threshold": 30.0,
            "window_seconds": 2,
        }),
        "threshold_value": 30.0,
        "time_window_seconds": 2,
        "severity": "CRITICAL",
        "is_enabled": True,
    },
    {
        "rule_name": "R-WLAN-03 (BSSID Spoofing Vector)",
        "suspicious_activity": "Rogue AP Beacon Spoofing",
        "protocol": "802.11",
        "detection_condition": json.dumps({
            "target_field": "frame_subtype",
            "match_value": 8,
            "disallowed_ouis": ["00:00:00", "FF:FF:FF"],
        }),
        "threshold_value": 10.0,
        "time_window_seconds": 5,
        "severity": "HIGH",
        "is_enabled": True,
    },
    {
        "rule_name": "R-WLAN-04 (Handshake Replay Anomaly)",
        "suspicious_activity": "WPA2/WPA3 4-Way Handshake Cracking",
        "protocol": "EAPOL",
        "detection_condition": json.dumps({
            "target_field": "protocol",
            "match_value": "EAPOL",
            "threshold": 5.0,
            "window_seconds": 2,
        }),
        "threshold_value": 5.0,
        "time_window_seconds": 2,
        "severity": "CRITICAL",
        "is_enabled": True,
    },
    {
        "rule_name": "R-WLAN-07 (Probe Request Burst Rate)",
        "suspicious_activity": "Excessive Probe Request Burst",
        "protocol": "802.11",
        "detection_condition": json.dumps({
            "target_field": "frame_subtype",
            "match_value": 4,
            "threshold": 50.0,
            "window_seconds": 5,
        }),
        "threshold_value": 50.0,
        "time_window_seconds": 5,
        "severity": "MEDIUM",
        "is_enabled": True,
    },
    {
        "rule_name": "R-WLAN-09 (KARMA Adaptive Beacon Response)",
        "suspicious_activity": "KARMA Attack SSID Beacon Response",
        "protocol": "802.11",
        "detection_condition": json.dumps({
            "target_field": "frame_subtype",
            "match_value": 5,
            "threshold": 10.0,
            "window_seconds": 2,
        }),
        "threshold_value": 10.0,
        "time_window_seconds": 2,
        "severity": "HIGH",
        "is_enabled": True,
    },
    {
        "rule_name": "R-WLAN-12 (Weak Initialization Vector)",
        "suspicious_activity": "Weak IV / WEP Frame Injection",
        "protocol": "802.11",
        "detection_condition": json.dumps({
            "target_field": "protocol",
            "match_value": "802.11",
            "threshold": 1.0,
            "window_seconds": 10,
        }),
        "threshold_value": 1.0,
        "time_window_seconds": 10,
        "severity": "LOW",
        "is_enabled": True,
    },
]


def init_database(db_engine=None, seed_defaults: bool = True) -> None:
    """Creates all database tables and seeds initial users and detection rules."""
    active_engine = db_engine or engine
    if active_engine is None:
        active_engine = init_engine()

    logger.info("Initializing database schema on %s...", active_engine.url)
    Base.metadata.create_all(bind=active_engine)

    if not seed_defaults:
        return

    session = SessionLocal() if SessionLocal else Session(bind=active_engine)
    try:
        user_repo = UserRepository(session)
        rule_repo = RuleRepository(session)

        # Seed users
        for u in INITIAL_USERS:
            existing = user_repo.get_by_username(u["username"])
            if not existing:
                user_repo.create(
                    username=u["username"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                )
                logger.info("Seeded default user '%s' (%s)", u["username"], u["role"])

        # Seed detection rules
        for r in INITIAL_RULES:
            existing = session.query(Detection_Rule).filter_by(rule_name=r["rule_name"]).first()
            if not existing:
                rule_repo.create(
                    rule_name=r["rule_name"],
                    suspicious_activity=r["suspicious_activity"],
                    protocol=r["protocol"],
                    detection_condition=r["detection_condition"],
                    threshold_value=r["threshold_value"],
                    time_window_seconds=r["time_window_seconds"],
                    severity=r["severity"],
                    is_enabled=r["is_enabled"],
                )
                logger.info("Seeded default detection rule '%s'", r["rule_name"])

        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error("Failed during database seeding: %s", exc)
        raise
    finally:
        session.close()
