"""Coordination: Pipeline Controller and Task Runner.

Provides job scheduling, asynchronous background task execution, and progress
tracking for PCAP file processing across E1, E2, E3, and E4.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Union

from backend.src.common.logger import get_logger
from .engine_coordinator import EngineCoordinator, default_engine_coordinator

logger = get_logger(__name__)


class JobStatus(str, Enum):
    """Pipeline job execution statuses."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


@dataclass
class JobRecord:
    """Status and result descriptor for a pipeline execution task."""

    job_id: str
    file_path: str
    user_id: Optional[Union[int, str]]
    batch_id: Optional[str]
    status: JobStatus = JobStatus.PENDING
    progress: int = 0
    submitted_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert job descriptor to plain dictionary."""
        return {
            "job_id": self.job_id,
            "file_path": self.file_path,
            "batch_id": self.batch_id,
            "status": self.status.value,
            "progress": self.progress,
            "submitted_at": self.submitted_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "result": self.result,
            "error": self.error,
        }


class PipelineController:
    """Manages synchronous and asynchronous pipeline jobs."""

    def __init__(
        self,
        coordinator: Optional[EngineCoordinator] = None,
        max_concurrent_jobs: int = 4,
    ) -> None:
        self.coordinator = coordinator or default_engine_coordinator
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=max_concurrent_jobs,
            thread_name_prefix="wntassoc-pipeline",
        )
        self._jobs: Dict[str, JobRecord] = {}
        self._lock = threading.Lock()

    def run_synchronous(
        self,
        file_path: Union[str, Path],
        user_id: Optional[Union[int, str]] = None,
        batch_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute pipeline synchronously and return processing summary immediately."""
        return self.coordinator.process_pcap_file(
            file_path=file_path,
            user_id=user_id,
            batch_id=batch_id,
        )

    def submit_job(
        self,
        file_path: Union[str, Path],
        user_id: Optional[Union[int, str]] = None,
        batch_id: Optional[str] = None,
    ) -> str:
        """Submit a PCAP processing job to run asynchronously in background.

        Returns:
            job_id string for polling job status.
        """
        job_id = f"job-{uuid.uuid4().hex[:12]}"
        record = JobRecord(
            job_id=job_id,
            file_path=str(file_path),
            user_id=user_id,
            batch_id=batch_id,
        )

        with self._lock:
            self._jobs[job_id] = record

        self.executor.submit(self._execute_job, job_id)
        logger.info("Submitted pipeline job %s for file %s", job_id, file_path)
        return job_id

    def _execute_job(self, job_id: str) -> None:
        with self._lock:
            record = self._jobs.get(job_id)
            if not record:
                return
            record.status = JobStatus.RUNNING
            record.started_at = datetime.now(timezone.utc).isoformat()
            record.progress = 10

        try:
            summary = self.coordinator.process_pcap_file(
                file_path=record.file_path,
                user_id=record.user_id,
                batch_id=record.batch_id,
            )
            with self._lock:
                record.status = JobStatus.COMPLETED
                record.progress = 100
                record.completed_at = datetime.now(timezone.utc).isoformat()
                record.result = summary
                record.batch_id = summary.get("batch_uuid")
        except Exception as exc:
            logger.error("Pipeline job %s failed: %s", job_id, exc)
            with self._lock:
                record.status = JobStatus.FAILED
                record.error = str(exc)
                record.completed_at = datetime.now(timezone.utc).isoformat()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve job descriptor by job_id."""
        with self._lock:
            rec = self._jobs.get(job_id)
            return rec.to_dict() if rec else None

    def list_jobs(self) -> List[Dict[str, Any]]:
        """List all tracked pipeline jobs."""
        with self._lock:
            return [rec.to_dict() for rec in self._jobs.values()]


# Shared default controller instance
default_pipeline_controller = PipelineController()
