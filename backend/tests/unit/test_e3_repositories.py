"""Unit tests for E3 repository layer and StorageEngine.

Uses an in-memory SQLite database via SQLAlchemy so the actual
PostgreSQL development database is never touched.

Coverage
--------
- UUID-to-integer PK mapping (batch, log, result, alert, error)
- Duplicate UUID handling (all five entities)
- Batch persistence
- Traffic-log persistence and bulk_create
- Processing-error persistence and bulk_create
- Enabled-rule retrieval
- Matched and unmatched detection-result persistence
- Alert persistence and 1-to-0-or-1 cardinality enforcement
- Transaction rollback on failure
- Pagination / list operations
- StorageEngine helpers: _parse_datetime, _serialize, _parse_uuid
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Generator

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from backend.src.database.base import Base
from backend.src.database.models import (
    Alert,
    Detection_Result,
    Detection_Rule,
    Log_Batch,
    Processing_Error,
    Traffic_Log,
    User,
)
from backend.src.engines.e3_log_alert_storage.alert_repository import AlertRepository
from backend.src.engines.e3_log_alert_storage.batch_repository import BatchRepository
from backend.src.engines.e3_log_alert_storage.error_repository import ErrorRepository
from backend.src.engines.e3_log_alert_storage.log_repository import LogRepository
from backend.src.engines.e3_log_alert_storage.result_repository import ResultRepository
from backend.src.engines.e3_log_alert_storage.rule_repository import RuleRepository
from backend.src.engines.e3_log_alert_storage.user_repository import UserRepository
from backend.src.engines.e3_log_alert_storage.storage_engine import (
    _parse_datetime,
    _parse_uuid,
    _serialize,
)


# ---------------------------------------------------------------------------
# SQLite in-memory test database setup
# ---------------------------------------------------------------------------

# PostgreSQL-specific types (UUID) and BigInteger autoincrement are adapted for SQLite tests.
# In SQLite, only INTEGER PRIMARY KEY columns autoincrement (BIGINT does not).
# We register custom compiler rules for SQLite to compile PG_UUID as CHAR(36) and BigInteger as INTEGER.
from sqlalchemy import BigInteger
from sqlalchemy.dialects.postgresql import UUID as _PG_UUID
from sqlalchemy.ext.compiler import compiles


@compiles(_PG_UUID, "sqlite")
def _compile_pg_uuid_sqlite(type_, compiler, **kw):
    return "CHAR(36)"


@compiles(BigInteger, "sqlite")
def _compile_bigint_sqlite(type_, compiler, **kw):
    return "INTEGER"


def _make_sqlite_engine():
    """Create a fresh SQLite in-memory engine with schema for every test session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    # Enable foreign key enforcement in SQLite
    @event.listens_for(engine, "connect")
    def _fk_pragma(dbapi_con, _record):
        dbapi_con.execute("PRAGMA foreign_keys=ON")

    Base.metadata.create_all(engine)
    return engine


@pytest.fixture(scope="module")
def db_engine():
    engine = _make_sqlite_engine()
    yield engine
    engine.dispose()


@pytest.fixture
def session(db_engine) -> Generator[Session, None, None]:
    """Provide a fresh transactional session rolled back after each test."""
    connection = db_engine.connect()
    trans = connection.begin()
    Session_ = sessionmaker(bind=connection)
    sess = Session_()
    yield sess
    sess.close()
    trans.rollback()
    connection.close()


# ---------------------------------------------------------------------------
# Common test helpers
# ---------------------------------------------------------------------------

def _make_user(session: Session, username: Optional[str] = None) -> User:
    repo = UserRepository(session)
    uname = username or f"user_{uuid.uuid4().hex[:8]}"
    return repo.create(username=uname, password_hash="hashed", role="analyst")


def _make_batch(session: Session, user_id: int, batch_uuid: uuid.UUID = None) -> Log_Batch:
    repo = BatchRepository(session)
    return repo.create(
        batch_uuid=batch_uuid or uuid.uuid4(),
        user_id=user_id,
        file_name="test.pcap",
        file_format="pcap",
        submitted_at=datetime.now(timezone.utc),
        processing_status="SUCCESS",
        total_records=10,
        processed_records=10,
        failed_records=0,
    )


def _make_traffic_log(session: Session, batch_id: int, log_uuid: uuid.UUID = None) -> Traffic_Log:
    repo = LogRepository(session)
    return repo.create(
        log_uuid=log_uuid or uuid.uuid4(),
        batch_id=batch_id,
        timestamp=datetime.now(timezone.utc),
        source_address="10.0.0.1",
        destination_address="10.0.0.2",
        protocol="TCP",
    )


def _make_rule(session: Session, rule_name: str = "TestRule", is_enabled: bool = True) -> Detection_Rule:
    repo = RuleRepository(session)
    return repo.create(
        rule_name=rule_name,
        suspicious_activity="PortScan",
        protocol="TCP",
        detection_condition="dst_port < 1024",
        severity="HIGH",
        is_enabled=is_enabled,
    )


def _make_result(
    session: Session,
    log_id: int,
    rule_id: int,
    matched: bool = True,
    result_uuid: uuid.UUID = None,
) -> Detection_Result:
    repo = ResultRepository(session)
    return repo.create(
        result_uuid=result_uuid or uuid.uuid4(),
        log_id=log_id,
        rule_id=rule_id,
        rule_match_status=matched,
        detection_time=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Tests: internal helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_parse_datetime_iso_z(self):
        dt = _parse_datetime("2026-11-12T17:00:00Z")
        assert dt.tzinfo is not None
        assert dt.year == 2026

    def test_parse_datetime_offset(self):
        dt = _parse_datetime("2026-11-12T17:00:00+05:30")
        assert dt.tzinfo is not None

    def test_parse_datetime_none(self):
        dt = _parse_datetime(None)
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None

    def test_parse_datetime_invalid(self):
        dt = _parse_datetime("not-a-date")
        assert isinstance(dt, datetime)
        assert dt.tzinfo is not None

    def test_serialize_dict(self):
        result = _serialize({"key": "value", "num": 42})
        parsed = json.loads(result)
        assert parsed["key"] == "value"

    def test_serialize_string_passthrough(self):
        assert _serialize("already a string") == "already a string"

    def test_serialize_none(self):
        assert _serialize(None) is None

    def test_parse_uuid_valid(self):
        u = uuid.uuid4()
        result = _parse_uuid(str(u))
        assert result == u

    def test_parse_uuid_invalid(self):
        assert _parse_uuid("not-a-uuid") is None

    def test_parse_uuid_none(self):
        assert _parse_uuid(None) is None


# ---------------------------------------------------------------------------
# Tests: UserRepository
# ---------------------------------------------------------------------------

class TestUserRepository:
    def test_create_and_retrieve_by_id(self, session):
        user = _make_user(session, "alice")
        fetched = UserRepository(session).get_by_id(user.user_id)
        assert fetched is not None
        assert fetched.username == "alice"

    def test_get_by_username(self, session):
        _make_user(session, "bob")
        result = UserRepository(session).get_by_username("bob")
        assert result is not None
        assert result.username == "bob"

    def test_get_by_username_not_found(self, session):
        assert UserRepository(session).get_by_username("nobody") is None

    def test_update_role(self, session):
        user = _make_user(session, "charlie")
        updated = UserRepository(session).update_role(user.user_id, "admin")
        assert updated.role == "admin"

    def test_list_all_pagination(self, session):
        repo = UserRepository(session)
        for i in range(5):
            repo.create(username=f"paguser{i}", password_hash="h", role="analyst")
        page1 = repo.list_all(offset=0, limit=3)
        page2 = repo.list_all(offset=3, limit=3)
        assert len(page1) == 3
        assert len(page2) >= 2  # at least the 2 remaining (may be more from prior tests)


# ---------------------------------------------------------------------------
# Tests: BatchRepository
# ---------------------------------------------------------------------------

class TestBatchRepository:
    def test_create_and_retrieve(self, session):
        user = _make_user(session)
        b_uuid = uuid.uuid4()
        batch = _make_batch(session, user.user_id, b_uuid)
        assert batch.batch_id is not None
        assert batch.batch_uuid == b_uuid

    def test_uuid_to_id_mapping(self, session):
        user = _make_user(session)
        b_uuid = uuid.uuid4()
        batch = _make_batch(session, user.user_id, b_uuid)
        repo = BatchRepository(session)
        resolved = repo.get_internal_id_by_uuid(b_uuid)
        assert resolved == batch.batch_id

    def test_exists_by_uuid_true(self, session):
        user = _make_user(session)
        b_uuid = uuid.uuid4()
        _make_batch(session, user.user_id, b_uuid)
        assert BatchRepository(session).exists_by_uuid(b_uuid) is True

    def test_exists_by_uuid_false(self, session):
        assert BatchRepository(session).exists_by_uuid(uuid.uuid4()) is False

    def test_duplicate_uuid_raises_integrity_error(self, session):
        user = _make_user(session)
        b_uuid = uuid.uuid4()
        _make_batch(session, user.user_id, b_uuid)
        with pytest.raises(IntegrityError):
            _make_batch(session, user.user_id, b_uuid)

    def test_update_status(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = BatchRepository(session)
        updated = repo.update_status(batch.batch_id, "FAILED", failed_records=5)
        assert updated.processing_status == "FAILED"
        assert updated.failed_records == 5

    def test_list_by_user_pagination(self, session):
        user = _make_user(session)
        repo = BatchRepository(session)
        for _ in range(4):
            _make_batch(session, user.user_id)
        page1 = repo.list_by_user(user.user_id, offset=0, limit=2)
        page2 = repo.list_by_user(user.user_id, offset=2, limit=2)
        assert len(page1) == 2
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Tests: LogRepository
# ---------------------------------------------------------------------------

class TestLogRepository:
    def test_create_and_retrieve(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        l_uuid = uuid.uuid4()
        log = _make_traffic_log(session, batch.batch_id, l_uuid)
        assert log.log_id is not None
        assert log.log_uuid == l_uuid

    def test_uuid_to_id_mapping(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        l_uuid = uuid.uuid4()
        log = _make_traffic_log(session, batch.batch_id, l_uuid)
        resolved = LogRepository(session).get_internal_id_by_uuid(l_uuid)
        assert resolved == log.log_id

    def test_duplicate_uuid_raises(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        l_uuid = uuid.uuid4()
        _make_traffic_log(session, batch.batch_id, l_uuid)
        with pytest.raises(IntegrityError):
            _make_traffic_log(session, batch.batch_id, l_uuid)

    def test_bulk_create_skips_duplicates(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        l_uuid = uuid.uuid4()
        _make_traffic_log(session, batch.batch_id, l_uuid)

        repo = LogRepository(session)
        new_uuid = uuid.uuid4()
        records = [
            {
                "log_uuid": l_uuid,  # duplicate — should be skipped
                "batch_id": batch.batch_id,
                "timestamp": datetime.now(timezone.utc),
                "source_address": "1.2.3.4",
                "destination_address": "5.6.7.8",
                "protocol": "UDP",
            },
            {
                "log_uuid": new_uuid,
                "batch_id": batch.batch_id,
                "timestamp": datetime.now(timezone.utc),
                "source_address": "1.2.3.5",
                "destination_address": "5.6.7.9",
                "protocol": "TCP",
            },
        ]
        created = repo.bulk_create(records)
        assert len(created) == 1
        assert created[0].log_uuid == new_uuid

    def test_list_by_batch_pagination(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = LogRepository(session)
        for _ in range(5):
            _make_traffic_log(session, batch.batch_id)
        page1 = repo.list_by_batch(batch.batch_id, offset=0, limit=3)
        page2 = repo.list_by_batch(batch.batch_id, offset=3, limit=3)
        assert len(page1) == 3
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Tests: RuleRepository
# ---------------------------------------------------------------------------

class TestRuleRepository:
    def test_create_and_retrieve(self, session):
        rule = _make_rule(session, "UniqueRule1")
        fetched = RuleRepository(session).get_by_id(rule.rule_id)
        assert fetched is not None
        assert fetched.rule_name == "UniqueRule1"

    def test_get_enabled_rules(self, session):
        repo = RuleRepository(session)
        _make_rule(session, "EnabledRuleA", is_enabled=True)
        _make_rule(session, "DisabledRuleB", is_enabled=False)
        enabled = repo.get_enabled_rules()
        names = [r.rule_name for r in enabled]
        assert "EnabledRuleA" in names
        assert "DisabledRuleB" not in names

    def test_set_enabled_toggle(self, session):
        rule = _make_rule(session, "ToggleRule")
        repo = RuleRepository(session)
        repo.set_enabled(rule.rule_id, False)
        fetched = repo.get_by_id(rule.rule_id)
        assert fetched.is_enabled is False

    def test_duplicate_rule_name_raises(self, session):
        _make_rule(session, "DuplicateRule")
        with pytest.raises(IntegrityError):
            _make_rule(session, "DuplicateRule")

    def test_list_all_pagination(self, session):
        repo = RuleRepository(session)
        for i in range(4):
            repo.create(
                rule_name=f"PagRule{i}_{uuid.uuid4().hex[:6]}",
                suspicious_activity="Test",
                protocol="ANY",
                detection_condition="cond",
                severity="LOW",
            )
        page = repo.list_all(offset=0, limit=2)
        assert len(page) == 2


# ---------------------------------------------------------------------------
# Tests: ResultRepository
# ---------------------------------------------------------------------------

class TestResultRepository:
    def _setup(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        log = _make_traffic_log(session, batch.batch_id)
        rule = _make_rule(session, f"RuleForResult_{uuid.uuid4().hex[:6]}")
        return log, rule

    def test_create_matched(self, session):
        log, rule = self._setup(session)
        result = _make_result(session, log.log_id, rule.rule_id, matched=True)
        assert result.result_id is not None
        assert result.rule_match_status is True

    def test_create_unmatched(self, session):
        log, rule = self._setup(session)
        result = _make_result(session, log.log_id, rule.rule_id, matched=False)
        assert result.rule_match_status is False

    def test_uuid_to_id_mapping(self, session):
        log, rule = self._setup(session)
        r_uuid = uuid.uuid4()
        result = _make_result(session, log.log_id, rule.rule_id, result_uuid=r_uuid)
        resolved = ResultRepository(session).get_internal_id_by_uuid(r_uuid)
        assert resolved == result.result_id

    def test_duplicate_result_uuid_raises(self, session):
        log, rule = self._setup(session)
        r_uuid = uuid.uuid4()
        _make_result(session, log.log_id, rule.rule_id, result_uuid=r_uuid)
        with pytest.raises(IntegrityError):
            _make_result(session, log.log_id, rule.rule_id, result_uuid=r_uuid)

    def test_list_matched(self, session):
        log, rule = self._setup(session)
        _make_result(session, log.log_id, rule.rule_id, matched=True)
        _make_result(session, log.log_id, rule.rule_id, matched=False)
        matched = ResultRepository(session).list_matched()
        assert all(r.rule_match_status is True for r in matched)

    def test_list_by_log_pagination(self, session):
        log, rule = self._setup(session)
        for _ in range(4):
            _make_result(session, log.log_id, rule.rule_id)
        repo = ResultRepository(session)
        page1 = repo.list_by_log(log.log_id, offset=0, limit=2)
        page2 = repo.list_by_log(log.log_id, offset=2, limit=2)
        assert len(page1) == 2
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Tests: AlertRepository
# ---------------------------------------------------------------------------

class TestAlertRepository:
    def _setup(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        log = _make_traffic_log(session, batch.batch_id)
        rule = _make_rule(session, f"AlertTestRule_{uuid.uuid4().hex[:6]}")
        result = _make_result(session, log.log_id, rule.rule_id)
        return result

    def test_create_alert(self, session):
        result = self._setup(session)
        repo = AlertRepository(session)
        a_uuid = uuid.uuid4()
        alert = repo.create(
            alert_uuid=a_uuid,
            result_id=result.result_id,
            alert_details='{"msg": "test"}',
            alert_timestamp=datetime.now(timezone.utc),
            severity="HIGH",
            alert_status="NEW",
        )
        assert alert.alert_id is not None
        assert alert.alert_uuid == a_uuid

    def test_duplicate_alert_uuid_raises(self, session):
        result = self._setup(session)
        repo = AlertRepository(session)
        a_uuid = uuid.uuid4()
        repo.create(
            alert_uuid=a_uuid,
            result_id=result.result_id,
            alert_details="{}",
            alert_timestamp=datetime.now(timezone.utc),
            severity="LOW",
            alert_status="NEW",
        )
        # Second alert with same uuid should raise
        result2 = self._setup(session)
        with pytest.raises(IntegrityError):
            repo.create(
                alert_uuid=a_uuid,
                result_id=result2.result_id,
                alert_details="{}",
                alert_timestamp=datetime.now(timezone.utc),
                severity="LOW",
                alert_status="NEW",
            )

    def test_one_to_one_cardinality_enforced_via_exists(self, session):
        result = self._setup(session)
        repo = AlertRepository(session)
        repo.create(
            alert_uuid=uuid.uuid4(),
            result_id=result.result_id,
            alert_details="{}",
            alert_timestamp=datetime.now(timezone.utc),
            severity="LOW",
            alert_status="NEW",
        )
        assert repo.exists_for_result(result.result_id) is True

    def test_update_status(self, session):
        result = self._setup(session)
        repo = AlertRepository(session)
        alert = repo.create(
            alert_uuid=uuid.uuid4(),
            result_id=result.result_id,
            alert_details="{}",
            alert_timestamp=datetime.now(timezone.utc),
            severity="MEDIUM",
            alert_status="NEW",
        )
        updated = repo.update_status(alert.alert_id, "RESOLVED")
        assert updated.alert_status == "RESOLVED"

    def test_list_all_pagination(self, session):
        repo = AlertRepository(session)
        for _ in range(3):
            result = self._setup(session)
            repo.create(
                alert_uuid=uuid.uuid4(),
                result_id=result.result_id,
                alert_details="{}",
                alert_timestamp=datetime.now(timezone.utc),
                severity="LOW",
                alert_status="NEW",
            )
        page = repo.list_all(offset=0, limit=2)
        assert len(page) == 2

    def test_get_by_result_id(self, session):
        result = self._setup(session)
        repo = AlertRepository(session)
        a_uuid = uuid.uuid4()
        created = repo.create(
            alert_uuid=a_uuid,
            result_id=result.result_id,
            alert_details="{}",
            alert_timestamp=datetime.now(timezone.utc),
            severity="CRITICAL",
            alert_status="NEW",
        )
        fetched = repo.get_by_result_id(result.result_id)
        assert fetched.alert_id == created.alert_id


# ---------------------------------------------------------------------------
# Tests: ErrorRepository
# ---------------------------------------------------------------------------

class TestErrorRepository:
    def test_create_and_retrieve(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = ErrorRepository(session)
        e_uuid = uuid.uuid4()
        error = repo.create(
            error_uuid=e_uuid,
            batch_id=batch.batch_id,
            error_type="ParseFailure",
            error_message="Bad packet",
            error_timestamp=datetime.now(timezone.utc),
        )
        assert error.error_id is not None
        assert error.error_uuid == e_uuid

    def test_duplicate_error_uuid_raises(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = ErrorRepository(session)
        e_uuid = uuid.uuid4()
        repo.create(
            error_uuid=e_uuid,
            batch_id=batch.batch_id,
            error_type="X",
            error_message="m",
            error_timestamp=datetime.now(timezone.utc),
        )
        with pytest.raises(IntegrityError):
            repo.create(
                error_uuid=e_uuid,
                batch_id=batch.batch_id,
                error_type="X",
                error_message="m",
                error_timestamp=datetime.now(timezone.utc),
            )

    def test_bulk_create_skips_duplicates(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = ErrorRepository(session)
        e_uuid = uuid.uuid4()
        repo.create(
            error_uuid=e_uuid,
            batch_id=batch.batch_id,
            error_type="X",
            error_message="m",
            error_timestamp=datetime.now(timezone.utc),
        )
        new_uuid = uuid.uuid4()
        records = [
            {
                "error_uuid": e_uuid,  # duplicate
                "batch_id": batch.batch_id,
                "error_type": "X",
                "error_message": "m",
                "error_timestamp": datetime.now(timezone.utc),
            },
            {
                "error_uuid": new_uuid,
                "batch_id": batch.batch_id,
                "error_type": "Y",
                "error_message": "n",
                "error_timestamp": datetime.now(timezone.utc),
            },
        ]
        created = repo.bulk_create(records)
        assert len(created) == 1
        assert created[0].error_uuid == new_uuid

    def test_list_by_batch_pagination(self, session):
        user = _make_user(session)
        batch = _make_batch(session, user.user_id)
        repo = ErrorRepository(session)
        for _ in range(4):
            repo.create(
                error_uuid=uuid.uuid4(),
                batch_id=batch.batch_id,
                error_type="T",
                error_message="e",
                error_timestamp=datetime.now(timezone.utc),
            )
        page1 = repo.list_by_batch(batch.batch_id, offset=0, limit=2)
        page2 = repo.list_by_batch(batch.batch_id, offset=2, limit=2)
        assert len(page1) == 2
        assert len(page2) == 2


# ---------------------------------------------------------------------------
# Tests: Transaction rollback
# ---------------------------------------------------------------------------

class TestTransactionRollback:
    def test_session_rollback_reverts_flush(self, db_engine):
        """Verify that rolling back a session reverts flushed but uncommitted data."""
        from sqlalchemy.orm import sessionmaker
        Session_ = sessionmaker(bind=db_engine)
        sess = Session_()
        try:
            user_repo = UserRepository(sess)
            u_name = f"rollback_user_{uuid.uuid4().hex[:8]}"
            user_repo.create(username=u_name, password_hash="h", role="analyst")
            sess.flush()
            # Verify exists before rollback
            assert user_repo.get_by_username(u_name) is not None
            sess.rollback()
            # After rollback, user should not exist
            assert user_repo.get_by_username(u_name) is None
        finally:
            sess.close()
