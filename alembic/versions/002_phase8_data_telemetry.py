"""Phase 8 data & telemetry tables

Revision ID: 002
Revises: 001
Create Date: 2026-08-19 00:00:00.000000

Adds:
  - sla_deadline column to vulnerabilities
  - ai_activity_logs (AI token/cost telemetry)
  - risk_exceptions (risk acceptance exceptions)
  - itsm_tickets (Jira / ServiceNow bi-directional sync)

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "002"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("sla_deadline", sa.DateTime(), nullable=True),
    )

    op.create_table(
        "ai_activity_logs",
        sa.Column("log_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("vulnerability_id", sa.String(64), nullable=True),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("model", sa.String(100), nullable=False),
        sa.Column("prompt_tokens", sa.Integer, nullable=False, default=0),
        sa.Column("completion_tokens", sa.Integer, nullable=False, default=0),
        sa.Column("total_tokens", sa.Integer, nullable=False, default=0),
        sa.Column("estimated_cost_usd", sa.Float, nullable=False, default=0.0),
        sa.Column("latency_ms", sa.Float, nullable=False, default=0.0),
        sa.Column("sanitizer_passed", sa.Boolean, nullable=False, default=True),
        sa.Column("prompt_hash", sa.String(64), nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=False, index=True),
    )

    op.create_table(
        "risk_exceptions",
        sa.Column("exception_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.vulnerability_id"),
            nullable=False,
        ),
        sa.Column("requester", sa.String(255), nullable=False),
        sa.Column("justification", sa.Text, nullable=False),
        sa.Column("compensating_controls", sa.Text, nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime, nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="ACTIVE"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_table(
        "itsm_tickets",
        sa.Column("ticket_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "vulnerability_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("vulnerabilities.vulnerability_id"),
            nullable=False,
        ),
        sa.Column("system_name", sa.String(64), nullable=False),
        sa.Column("external_ticket_id", sa.String(128), nullable=False),
        sa.Column("ticket_url", sa.String(255), nullable=True),
        sa.Column("status", sa.String(64), nullable=False, default="OPEN"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    op.create_index("ix_risk_exceptions_vulnerability_id", "risk_exceptions", ["vulnerability_id"])
    op.create_index("ix_itsm_tickets_vulnerability_id", "itsm_tickets", ["vulnerability_id"])


def downgrade() -> None:
    op.drop_index("ix_itsm_tickets_vulnerability_id", table_name="itsm_tickets")
    op.drop_index("ix_risk_exceptions_vulnerability_id", table_name="risk_exceptions")
    op.drop_table("itsm_tickets")
    op.drop_table("risk_exceptions")
    op.drop_table("ai_activity_logs")
    op.drop_column("vulnerabilities", "sla_deadline")
