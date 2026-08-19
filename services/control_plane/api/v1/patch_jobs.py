import time
import uuid
from datetime import UTC, datetime
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit.ledger import AuditLedger
from services.control_plane.core.db import get_db
from services.models.db_models import Asset, PatchJob, RemediationPlan
from services.models.domain_schemas import PatchJobCreate, PatchJobExecutionResult, PatchJobResponse
from services.observability.metrics import record_patch_execution_duration, record_patch_job
from services.orchestrator.engine import OrchestrationEngine

router = APIRouter(prefix="/patch-jobs", tags=["Patch Jobs"])
orchestrator = OrchestrationEngine()


@router.post("", response_model=PatchJobResponse, status_code=201)
async def create_patch_job(job_in: PatchJobCreate, db: AsyncSession = Depends(get_db)):
    plan = await db.get(RemediationPlan, job_in.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation Plan not found")

    job = PatchJob(
        plan_id=job_in.plan_id,
        execution_type=job_in.execution_type,
        status="QUEUED",
        execution_logs=[],
        snapshot_metadata={},
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    return job


@router.get("", response_model=List[PatchJobResponse])
async def list_patch_jobs(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(PatchJob).order_by(PatchJob.started_at.desc()))
    return result.scalars().all()


@router.post("/{job_id}/rollback", response_model=PatchJobResponse)
async def rollback_patch_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    """Trigger emergency rollback of a patch job."""
    job = await db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch Job not found")
    if not job.rollback_available:
        raise HTTPException(status_code=409, detail="Job rollback not available")

    plan = await db.get(RemediationPlan, job.plan_id)
    rollback_commands = (
        [
            action.get("rollback_command_template")
            for action in (plan.plan_payload or {}).get("actions", [])
            if action.get("rollback_command_template")
        ]
        if plan
        else []
    )

    job.status = "ROLLED_BACK"
    job.execution_logs = [*job.execution_logs, "Emergency rollback triggered"]
    job.snapshot_metadata = {**job.snapshot_metadata, "rollback": {"commands": rollback_commands}}
    job.completed_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()

    await AuditLedger.log_event(
        db,
        actor="Operator",
        action="PATCH_ROLLED_BACK",
        payload={
            "job_id": str(job.job_id),
            "plan_id": str(job.plan_id),
            "rollback_commands": rollback_commands,
        },
    )
    record_patch_job("ROLLED_BACK")
    await db.refresh(job)
    return job


@router.get("/{job_id}", response_model=PatchJobResponse)
async def get_patch_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch Job not found")
    return job


@router.post("/{job_id}/execute", response_model=PatchJobExecutionResult)
async def execute_patch_job(job_id: uuid.UUID, db: AsyncSession = Depends(get_db)):
    job = await db.get(PatchJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Patch Job not found")

    plan = await db.get(RemediationPlan, job.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation Plan not found")
    if plan.status != "APPROVED":
        raise HTTPException(
            status_code=409,
            detail=f"Plan status must be APPROVED before execution (current: {plan.status})",
        )

    asset = await db.get(Asset, plan.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    actions = plan.plan_payload.get("actions", [])
    if not actions:
        raise HTTPException(status_code=409, detail="Plan has no actions to execute")

    job.status = "RUNNING"
    job.started_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()

    exec_start = time.monotonic()
    result = await orchestrator.run_remediation(
        host=asset.hostname,
        os_type=asset.os_type,
        actions=actions,
        credentials={},
    )
    exec_duration = time.monotonic() - exec_start
    record_patch_execution_duration(job.execution_type, exec_duration)

    job.status = result["overall_status"]
    record_patch_job(job.status)
    job.execution_logs = [log for action in result["actions"] for log in action.get("logs", [])]
    job.snapshot_metadata = {
        action.get("target_package"): action.get("snapshot_metadata", {})
        for action in result["actions"]
        if action.get("snapshot_metadata")
    }
    job.completed_at = datetime.now(UTC).replace(tzinfo=None)
    await db.commit()
    await db.refresh(job)

    plan.status = "EXECUTED" if job.status == "SUCCESS" else "FAILED"
    await db.commit()

    await AuditLedger.log_event(
        db,
        actor="OrchestrationEngine",
        action="PATCH_EXECUTED",
        payload={
            "job_id": str(job.job_id),
            "plan_id": str(plan.plan_id),
            "overall_status": job.status,
            "snapshot_summary": result.get("snapshot_summary"),
        },
    )

    return PatchJobExecutionResult(
        job_id=job.job_id,
        plan_id=plan.plan_id,
        overall_status=job.status,
        action_count=result["action_count"],
        actions=result["actions"],
    )
