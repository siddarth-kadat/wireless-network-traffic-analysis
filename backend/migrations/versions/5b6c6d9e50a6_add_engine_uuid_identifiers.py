
"""Add engine UUID identifiers.

Revision ID: 5b6c6d9e50a6
Revises: 20f8df5e251f
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "5b6c6d9e50a6"
down_revision: Union[str, None] = "20f8df5e251f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


UUID_COLUMNS = [
    ("alerts", "alert_uuid", "uq_alerts_alert_uuid"),
    (
        "detection_results",
        "result_uuid",
        "uq_detection_results_result_uuid",
    ),
    ("log_batches", "batch_uuid", "uq_log_batches_batch_uuid"),
    (
        "processing_errors",
        "error_uuid",
        "uq_processing_errors_error_uuid",
    ),
    ("traffic_logs", "log_uuid", "uq_traffic_logs_log_uuid"),
]


def upgrade() -> None:
    # Step 1: Add UUID columns as nullable.
    for table, column, constraint in UUID_COLUMNS:
        op.add_column(
            table,
            sa.Column(
                column,
                postgresql.UUID(as_uuid=True),
                nullable=True,
            ),
        )

    # Step 2: Backfill UUID values for existing records.
    for table, column, constraint in UUID_COLUMNS:
        op.execute(
            sa.text(
                f'UPDATE "{table}" '
                f'SET "{column}" = gen_random_uuid() '
                f'WHERE "{column}" IS NULL'
            )
        )

    # Step 3: Enforce NOT NULL and create named unique constraints.
    for table, column, constraint in UUID_COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=postgresql.UUID(as_uuid=True),
            nullable=False,
        )

        op.create_unique_constraint(
            constraint,
            table,
            [column],
        )


def downgrade() -> None:
    # Remove only the UUID constraints and columns added by this migration.
    for table, column, constraint in reversed(UUID_COLUMNS):
        op.drop_constraint(
            constraint,
            table,
            type_="unique",
        )
        op.drop_column(table, column)
