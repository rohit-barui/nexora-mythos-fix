import uuid
from datetime import UTC, datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now_naive() -> datetime:
    """Naive UTC timestamp (matches legacy utcnow semantics without deprecation)."""
    return datetime.now(UTC).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class Asset(Base):
    __tablename__ = "assets"

    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    os_type: Mapped[str] = mapped_column(
        String(100), nullable=False
    )  # debian, rhel, windows, alpine, k8s, aws_ssm
    environment: Mapped[str] = mapped_column(
        String(50), nullable=False, default="production"
    )  # prod, staging, dev
    criticality_score: Mapped[int] = mapped_column(Integer, nullable=False, default=5)  # 1-10 scale
    exposure_level: Mapped[str] = mapped_column(
        String(50), nullable=False, default="internal"
    )  # internet-facing, internal, isolated
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now_naive, onupdate=_utc_now_naive
    )

    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability", back_populates="asset", cascade="all, delete-orphan"
    )
    plans: Mapped[List["RemediationPlan"]] = relationship(
        "RemediationPlan", back_populates="asset", cascade="all, delete-orphan"
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cve_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("assets.asset_id"), nullable=False)
    package_name: Mapped[str] = mapped_column(String(255), nullable=False)
    installed_version: Mapped[str] = mapped_column(String(100), nullable=False)
    fixed_version: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    cvss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    epss_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )  # CISA KEV flag

    calculated_risk_score: Mapped[float] = mapped_column(
        Float, nullable=False, default=0.0, index=True
    )
    scanner_source: Mapped[str] = mapped_column(
        String(100), nullable=False, default="trivy"
    )  # qualys, rapid7, nessus, trivy
    raw_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="OPEN"
    )  # OPEN, IN_REMEDIATION, RESOLVED, IGNORED
    sla_deadline: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="vulnerabilities")


class RemediationPlan(Base):
    __tablename__ = "remediation_plans"

    plan_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("assets.asset_id"), nullable=False)
    vulnerability_ids: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)

    generated_by_llm: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    planner_model: Mapped[str] = mapped_column(String(100), nullable=False, default="gpt-4o-mini")

    plan_payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)  # Actions array JSON
    opa_evaluation_result: Mapped[Dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )

    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="PENDING_POLICY"
    )  # PENDING_POLICY, PENDING_APPROVAL, APPROVED, REJECTED, EXECUTED, FAILED
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="plans")
    approval: Mapped[Optional["Approval"]] = relationship(
        "Approval", back_populates="plan", uselist=False
    )
    patch_jobs: Mapped[List["PatchJob"]] = relationship("PatchJob", back_populates="plan")


class Approval(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("remediation_plans.plan_id"), nullable=False
    )
    approver: Mapped[str] = mapped_column(
        String(255), nullable=False
    )  # User email or Teams bot user ID
    decision: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # APPROVED, REJECTED, MODIFIED
    comments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    channel: Mapped[str] = mapped_column(
        String(50), nullable=False, default="WEB_DASHBOARD"
    )  # WEB_DASHBOARD, TEAMS_BOT, SLACK
    decided_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)

    plan: Mapped["RemediationPlan"] = relationship("RemediationPlan", back_populates="approval")


class PatchJob(Base):
    __tablename__ = "patch_jobs"

    job_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    plan_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("remediation_plans.plan_id"), nullable=False
    )
    execution_type: Mapped[str] = mapped_column(
        String(50), nullable=False
    )  # AGENTLESS_SSH, WINRM, K8S_ROLLOUT, VIRTUAL_PATCH
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="QUEUED"
    )  # QUEUED, RUNNING, SUCCESS, FAILED, ROLLED_BACK

    execution_logs: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    rollback_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    snapshot_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    plan: Mapped["RemediationPlan"] = relationship("RemediationPlan", back_populates="patch_jobs")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    event_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    actor: Mapped[str] = mapped_column(
        String(255), nullable=False, index=True
    )  # System, User, LLM Planner, OPA Engine
    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )  # VULN_INGESTED, PLAN_GENERATED, POLICY_PASSED, APPROVAL, PATCH_EXECUTED, ROLLBACK
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    previous_event_hash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True
    )  # Merkle tree hash chain
    event_hash: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # SHA-256 (payload + prev_hash)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive, index=True)


class AIActivityLog(Base):
    __tablename__ = "ai_activity_logs"

    log_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(100), nullable=False)
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    latency_ms: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sanitizer_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    prompt_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive, index=True)


class RiskException(Base):
    __tablename__ = "risk_exceptions"

    exception_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("vulnerabilities.vulnerability_id"), nullable=False
    )
    requester: Mapped[str] = mapped_column(String(255), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    compensating_controls: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    approved_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="ACTIVE"
    )  # ACTIVE, EXPIRED, REVOKED
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)


class ITSMTicket(Base):
    __tablename__ = "itsm_tickets"

    ticket_id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("vulnerabilities.vulnerability_id"), nullable=False
    )
    system_name: Mapped[str] = mapped_column(String(64), nullable=False)  # JIRA, SERVICENOW
    external_ticket_id: Mapped[str] = mapped_column(String(128), nullable=False)
    ticket_url: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="OPEN")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utc_now_naive)
