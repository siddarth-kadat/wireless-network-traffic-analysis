"""SQLAlchemy ORM models representing the 7 approved database entities.

Entities:
1. User: Stores user account details and credentials.
2. Log_Batch: Metadata for uploaded network traffic log batches.
3. Traffic_Log: Individual processed wireless network traffic records.
4. Detection_Rule: Predefined detection rules and anomaly thresholds.
5. Detection_Result: Evaluation results of traffic logs against rules.
6. Alert: Security alerts generated from suspicious detection results.
7. Processing_Error: Errors during ingestion, parsing, and processing.
"""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.src.database.base import Base


class User(Base):
    """User entity storing credentials and role information for authentication."""

    __tablename__ = "users"

    user_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationship: User (1) -> Log_Batch (N)
    batches: Mapped[List[Log_Batch]] = relationship("Log_Batch", back_populates="user")


class Log_Batch(Base):
    """Log_Batch entity tracking batch metadata for uploaded log files."""

    __tablename__ = "log_batches"

    batch_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.user_id"), nullable=False, index=True)
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_format: Mapped[str] = mapped_column(String(50), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    processing_status: Mapped[str] = mapped_column(String(50), nullable=False)
    total_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    processed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_records: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Relationships
    user: Mapped[User] = relationship("User", back_populates="batches")
    traffic_logs: Mapped[List[Traffic_Log]] = relationship("Traffic_Log", back_populates="batch")
    processing_errors: Mapped[List[Processing_Error]] = relationship("Processing_Error", back_populates="batch")


class Traffic_Log(Base):
    """Traffic_Log entity representing individual processed network traffic events."""

    __tablename__ = "traffic_logs"

    log_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[int] = mapped_column(Integer, ForeignKey("log_batches.batch_id"), nullable=False, index=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    source_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    destination_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    source_mac: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    destination_mac: Mapped[Optional[str]] = mapped_column(String(17), nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    log_details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Relationships
    batch: Mapped[Log_Batch] = relationship("Log_Batch", back_populates="traffic_logs")
    detection_results: Mapped[List[Detection_Result]] = relationship("Detection_Result", back_populates="traffic_log")
    processing_errors: Mapped[List[Processing_Error]] = relationship("Processing_Error", back_populates="traffic_log")


class Detection_Rule(Base):
    """Detection_Rule entity defining deterministic rules and anomaly thresholds."""

    __tablename__ = "detection_rules"

    rule_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    suspicious_activity: Mapped[str] = mapped_column(String(100), nullable=False)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)
    detection_condition: Mapped[str] = mapped_column(Text, nullable=False)
    threshold_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    time_window_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Relationship: Detection_Rule (1) -> Detection_Result (N)
    detection_results: Mapped[List[Detection_Result]] = relationship("Detection_Result", back_populates="rule")


class Detection_Result(Base):
    """Detection_Result entity storing evaluation outcome of traffic logs against rules."""

    __tablename__ = "detection_results"

    result_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    log_id: Mapped[int] = mapped_column(BigInteger, ForeignKey("traffic_logs.log_id"), nullable=False, index=True)
    rule_id: Mapped[int] = mapped_column(Integer, ForeignKey("detection_rules.rule_id"), nullable=False, index=True)
    rule_match_status: Mapped[bool] = mapped_column(Boolean, nullable=False)
    observed_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    threshold_value: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    detection_evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    detection_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Relationships
    traffic_log: Mapped[Traffic_Log] = relationship("Traffic_Log", back_populates="detection_results")
    rule: Mapped[Detection_Rule] = relationship("Detection_Rule", back_populates="detection_results")
    alert: Mapped[Optional[Alert]] = relationship("Alert", back_populates="detection_result", uselist=False)


class Alert(Base):
    """Alert entity generated when a suspicious detection result occurs."""

    __tablename__ = "alerts"

    alert_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    result_id: Mapped[int] = mapped_column(
        BigInteger,
        ForeignKey("detection_results.result_id"),
        unique=True,
        nullable=False,
        index=True,
    )
    alert_details: Mapped[str] = mapped_column(Text, nullable=False)
    alert_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    alert_status: Mapped[str] = mapped_column(String(30), nullable=False)

    # Relationship: Detection_Result (1) -> Alert (0..1)
    detection_result: Mapped[Detection_Result] = relationship("Detection_Result", back_populates="alert")


class Processing_Error(Base):
    """Processing_Error entity recording failures during log parsing and processing."""

    __tablename__ = "processing_errors"

    error_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    batch_id: Mapped[int] = mapped_column(Integer, ForeignKey("log_batches.batch_id"), nullable=False, index=True)
    log_id: Mapped[Optional[int]] = mapped_column(
        BigInteger,
        ForeignKey("traffic_logs.log_id"),
        nullable=True,
        index=True,
    )
    error_type: Mapped[str] = mapped_column(String(100), nullable=False)
    error_message: Mapped[str] = mapped_column(Text, nullable=False)
    error_timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # Relationships
    batch: Mapped[Log_Batch] = relationship("Log_Batch", back_populates="processing_errors")
    traffic_log: Mapped[Optional[Traffic_Log]] = relationship("Traffic_Log", back_populates="processing_errors")
