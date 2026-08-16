import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.audit.ledger import GENESIS_HASH, AuditLedger, compute_event_hash
from services.models.db_models import AuditEvent, Base
from services.orchestrator.engine import OrchestrationEngine


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


def test_compute_event_hash_deterministic():
    h1 = compute_event_hash("system", "PATCH_EXECUTED", {"a": 1}, GENESIS_HASH)
    h2 = compute_event_hash("system", "PATCH_EXECUTED", {"a": 1}, GENESIS_HASH)
    assert h1 == h2
    h3 = compute_event_hash("system", "PATCH_EXECUTED", {"a": 2}, GENESIS_HASH)
    assert h1 != h3


@pytest.mark.asyncio
async def test_audit_ledger_chains_events(db):
    first = await AuditLedger.log_event(db, "system", "PLAN_GENERATED", {"plan_id": "1"})
    second = await AuditLedger.log_event(
        db, "admin", "APPROVAL_DECISION", {"plan_id": "1", "decision": "APPROVED"}
    )
    third = await AuditLedger.log_event(db, "engine", "PATCH_EXECUTED", {"plan_id": "1"})

    assert first.previous_event_hash == GENESIS_HASH
    assert second.previous_event_hash == first.event_hash
    assert third.previous_event_hash == second.event_hash

    verify = await AuditLedger.verify_chain(db)
    assert verify["valid"] is True
    assert verify["event_count"] == 3


@pytest.mark.asyncio
async def test_audit_ledger_detects_tampering(db):
    await AuditLedger.log_event(db, "system", "PLAN_GENERATED", {"plan_id": "1"})
    await AuditLedger.log_event(
        db, "admin", "APPROVAL_DECISION", {"plan_id": "1", "decision": "APPROVED"}
    )

    result = await db.execute(select(AuditEvent))
    events = list(result.scalars().all())
    events[1].payload = {"plan_id": "1", "decision": "REJECTED"}  # tamper
    await db.commit()

    verify = await AuditLedger.verify_chain(db)
    assert verify["valid"] is False
    assert any("Hash mismatch" in issue for issue in verify["issues"])


@pytest.mark.asyncio
async def test_orchestration_engine_runs_remediation():
    engine = OrchestrationEngine()
    result = await engine.run_remediation(
        host="web-01",
        os_type="debian",
        actions=[
            {
                "action_type": "patch",
                "target_package": "openssl",
                "method": "apt",
                "target_version": "3.0.3",
            }
        ],
    )
    assert result["overall_status"] == "SUCCESS"
    assert result["actions"][0]["status"] == "SUCCESS"
    assert result["snapshot_summary"]["snapshot_ids"][0].startswith("snap-")


@pytest.mark.asyncio
async def test_orchestration_engine_rolls_back_on_verification_failure(monkeypatch):
    from services.execution_engine.executor import PatchExecutor
    from services.orchestrator.activities import set_executor

    async def fake_verify(action, dry_run_cmds):
        return False

    # Use a shared executor instance so the activities module sees it
    executor = PatchExecutor()
    monkeypatch.setattr(executor, "_verify", fake_verify)
    set_executor(executor)

    engine = OrchestrationEngine(executor=executor)
    result = await engine.run_remediation(
        host="web-01",
        os_type="debian",
        actions=[{"action_type": "patch", "target_package": "openssl", "method": "apt"}],
    )
    assert result["overall_status"] == "ROLLED_BACK"
    set_executor(None)  # reset
