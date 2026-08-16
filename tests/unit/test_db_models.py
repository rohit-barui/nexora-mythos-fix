import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.models.db_models import (
    Approval,
    Asset,
    AuditEvent,
    Base,
    PatchJob,
    RemediationPlan,
    Vulnerability,
)


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.mark.asyncio
async def test_asset_and_vulnerability_crud(db):
    asset = Asset(
        hostname="web-01",
        os_type="debian",
        environment="production",
        criticality_score=8,
        exposure_level="internet-facing",
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    assert asset.asset_id is not None
    assert isinstance(asset.asset_id, uuid.UUID)

    vuln = Vulnerability(
        asset_id=asset.asset_id,
        cve_id="CVE-2022-3786",
        package_name="openssl",
        installed_version="3.0.2",
        fixed_version="3.0.3",
        cvss_score=9.8,
        epss_score=0.95,
        is_known_exploited=True,
        calculated_risk_score=9.66,
        raw_metadata={"source": "trivy", "tags": ["ssl"]},
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)

    assert vuln.vulnerability_id is not None
    assert vuln.status == "OPEN"
    assert vuln.raw_metadata["source"] == "trivy"

    result = await db.execute(select(Vulnerability).where(Vulnerability.cve_id == "CVE-2022-3786"))
    fetched = result.scalar_one()
    assert fetched.package_name == "openssl"
    assert fetched.is_known_exploited is True


@pytest.mark.asyncio
async def test_remediation_plan_and_approval_relationship(db):
    asset = Asset(hostname="db-01", os_type="rhel", criticality_score=9)
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    plan = RemediationPlan(
        asset_id=asset.asset_id,
        vulnerability_ids=["vuln-1"],
        generated_by_llm=True,
        planner_model="gpt-4o-mini",
        plan_payload={"actions": [{"action_type": "patch", "target_package": "openssl"}]},
        opa_evaluation_result={"allowed": True, "violations": []},
        status="PENDING_APPROVAL",
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)

    assert plan.plan_id is not None
    assert plan.plan_payload["actions"][0]["target_package"] == "openssl"

    approval = Approval(
        plan_id=plan.plan_id,
        approver="admin@nexora.io",
        decision="APPROVED",
        comments="ok to proceed",
        channel="WEB_DASHBOARD",
    )
    db.add(approval)
    await db.commit()

    result = await db.execute(select(Approval).where(Approval.plan_id == plan.plan_id))
    fetched_approval = result.scalar_one()
    assert fetched_approval.decision == "APPROVED"
    assert fetched_approval.plan is plan


@pytest.mark.asyncio
async def test_patch_job_and_audit_event(db):
    asset = Asset(hostname="k8s-01", os_type="k8s")
    db.add(asset)
    await db.commit()
    await db.refresh(asset)

    plan = RemediationPlan(
        asset_id=asset.asset_id,
        vulnerability_ids=[],
        plan_payload={"actions": []},
        opa_evaluation_result={},
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)

    job = PatchJob(
        plan_id=plan.plan_id,
        execution_type="K8S_ROLLOUT",
        execution_logs=["started rollout"],
        snapshot_metadata={"rollback": "available"},
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    assert job.status == "QUEUED"
    assert job.rollback_available is True
    assert job.execution_logs == ["started rollout"]

    event = AuditEvent(
        actor="System",
        action="PLAN_GENERATED",
        payload={"plan_id": str(plan.plan_id)},
        event_hash="abc123",
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    assert event.event_id is not None
    assert event.timestamp is not None
