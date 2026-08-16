"""Initial schema migration

Revision ID: 001
Revises:
Create Date: 2026-08-17 00:00:00.000000

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # assets table
    op.create_table(
        "assets",
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False, index=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("os_type", sa.String(100), nullable=False),
        sa.Column("environment", sa.String(50), nullable=False, default="production"),
        sa.Column("criticality_score", sa.Integer, nullable=False, default=5),
        sa.Column("exposure_level", sa.String(50), nullable=False, default="internal"),
        sa.Column("created_at", sa.DateTime, nullable=False),
        sa.Column("updated_at", sa.DateTime, nullable=False),
    )

    # vulnerabilities table
    op.create_table(
        "vulnerabilities",
        sa.Column("vulnerability_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("cve_id", sa.String(100), nullable=False, index=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.asset_id"),
            nullable=False,
        ),
        sa.Column("package_name", sa.String(255), nullable=False),
        sa.Column("installed_version", sa.String(100), nullable=False),
        sa.Column("fixed_version", sa.String(100), nullable=True),
        sa.Column("cvss_score", sa.Float, nullable=False, default=0.0),
        sa.Column("epss_score", sa.Float, nullable=False, default=0.0),
        sa.Column("is_known_exploited", sa.Boolean, nullable=False, default=False),
        sa.Column("calculated_risk_score", sa.Float, nullable=False, default=0.0, index=True),
        sa.Column("scanner_source", sa.String(100), nullable=False, default="trivy"),
        sa.Column("raw_metadata", sa.JSON, nullable=False, default=dict),
        sa.Column("status", sa.String(50), nullable=False, default="OPEN"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # remediation_plans table
    op.create_table(
        "remediation_plans",
        sa.Column("plan_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "asset_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("assets.asset_id"),
            nullable=False,
        ),
        sa.Column("vulnerability_ids", sa.JSON, nullable=False, default=list),
        sa.Column("generated_by_llm", sa.Boolean, nullable=False, default=True),
        sa.Column("planner_model", sa.String(100), nullable=False, default="gpt-4o-mini"),
        sa.Column("plan_payload", sa.JSON, nullable=False),
        sa.Column("opa_evaluation_result", sa.JSON, nullable=False, default=dict),
        sa.Column("status", sa.String(50), nullable=False, default="PENDING_POLICY"),
        sa.Column("created_at", sa.DateTime, nullable=False),
    )

    # approvals table
    op.create_table(
        "approvals",
        sa.Column("approval_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_plans.plan_id"),
            nullable=False,
        ),
        sa.Column("approver", sa.String(255), nullable=False),
        sa.Column("decision", sa.String(50), nullable=False),
        sa.Column("comments", sa.Text, nullable=True),
        sa.Column("channel", sa.String(50), nullable=False, default="WEB_DASHBOARD"),
        sa.Column("decided_at", sa.DateTime, nullable=False),
    )

    # patch_jobs table
    op.create_table(
        "patch_jobs",
        sa.Column("job_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "plan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("remediation_plans.plan_id"),
            nullable=False,
        ),
        sa.Column("execution_type", sa.String(50), nullable=False),
        sa.Column("status", sa.String(50), nullable=False, default="QUEUED"),
        sa.Column("execution_logs", sa.JSON, nullable=False, default=list),
        sa.Column("rollback_available", sa.Boolean, nullable=False, default=True),
        sa.Column("snapshot_metadata", sa.JSON, nullable=False, default=dict),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("completed_at", sa.DateTime, nullable=True),
    )

    # audit_events table
    op.create_table(
        "audit_events",
        sa.Column("event_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("actor", sa.String(255), nullable=False, index=True),
        sa.Column("action", sa.String(100), nullable=False, index=True),
        sa.Column("payload", sa.JSON, nullable=False),
        sa.Column("previous_event_hash", sa.String(64), nullable=True),
        sa.Column("event_hash", sa.String(64), nullable=False),
        sa.Column("timestamp", sa.DateTime, nullable=False, index=True),
    )

    # Indexes
    op.create_index("ix_vulnerabilities_asset_id", "vulnerabilities", ["asset_id"])
    op.create_index("ix_remediation_plans_asset_id", "remediation_plans", ["asset_id"])
    op.create_index("ix_patch_jobs_plan_id", "patch_jobs", ["plan_id"])
    op.create_index("ix_approvals_plan_id", "approvals", ["plan_id"])


def downgrade() -> None:
    op.drop_table("audit_events")
    op.drop_table("patch_jobs")
    op.drop_table("approvals")
    op.drop_table("remediation_plans")
    op.drop_table("vulnerabilities")
    op.drop_table("assets")
