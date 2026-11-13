"""E3: Log and Alert Storage Engine module.

Public API
----------
StorageEngine     — primary gateway; use this in production code.
UserRepository    — user CRUD.
BatchRepository   — batch CRUD + UUID mapping.
LogRepository     — traffic-log CRUD + UUID mapping.
RuleRepository    — detection-rule read + enabled-rule list.
ResultRepository  — detection-result CRUD + UUID mapping.
AlertRepository   — alert CRUD + UUID mapping.
ErrorRepository   — processing-error CRUD + UUID mapping.
"""

from .storage_engine import StorageEngine
from .user_repository import UserRepository
from .batch_repository import BatchRepository
from .log_repository import LogRepository
from .rule_repository import RuleRepository
from .result_repository import ResultRepository
from .alert_repository import AlertRepository
from .error_repository import ErrorRepository

__all__ = [
    "StorageEngine",
    "UserRepository",
    "BatchRepository",
    "LogRepository",
    "RuleRepository",
    "ResultRepository",
    "AlertRepository",
    "ErrorRepository",
]
