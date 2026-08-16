from datetime import UTC, datetime, timedelta
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit.ledger import AuditLedger
from services.control_plane.core.db import get_db
from services.models.db_models import Asset, AuditEvent, PatchJob, RemediationPlan, Vulnerability

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def dashboard_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Aggregate dashboard statistics."""
    total_assets = await db.scalar(select(func.count(Asset.asset_id)))
    total_vulns = await db.scalar(select(func.count(Vulnerability.vulnerability_id)))
    critical_vulns = await db.scalar(
        select(func.count(Vulnerability.vulnerability_id)).where(
            Vulnerability.calculated_risk_score >= 7.5
        )
    )
    open_vulns = await db.scalar(
        select(func.count(Vulnerability.vulnerability_id)).where(Vulnerability.status == "OPEN")
    )
    total_plans = await db.scalar(select(func.count(RemediationPlan.plan_id)))
    pending_approval = await db.scalar(
        select(func.count(RemediationPlan.plan_id)).where(
            RemediationPlan.status == "PENDING_APPROVAL"
        )
    )
    approved_plans = await db.scalar(
        select(func.count(RemediationPlan.plan_id)).where(RemediationPlan.status == "APPROVED")
    )
    executed_plans = await db.scalar(
        select(func.count(RemediationPlan.plan_id)).where(RemediationPlan.status == "EXECUTED")
    )
    total_jobs = await db.scalar(select(func.count(PatchJob.job_id)))
    successful_jobs = await db.scalar(
        select(func.count(PatchJob.job_id)).where(PatchJob.status == "SUCCESS")
    )
    failed_jobs = await db.scalar(
        select(func.count(PatchJob.job_id)).where(PatchJob.status == "FAILED")
    )
    rolled_back_jobs = await db.scalar(
        select(func.count(PatchJob.job_id)).where(PatchJob.status == "ROLLED_BACK")
    )

    return {
        "assets": {"total": total_assets or 0},
        "vulnerabilities": {
            "total": total_vulns or 0,
            "critical": critical_vulns or 0,
            "open": open_vulns or 0,
        },
        "remediation_plans": {
            "total": total_plans or 0,
            "pending_approval": pending_approval or 0,
            "approved": approved_plans or 0,
            "executed": executed_plans or 0,
        },
        "patch_jobs": {
            "total": total_jobs or 0,
            "successful": successful_jobs or 0,
            "failed": failed_jobs or 0,
            "rolled_back": rolled_back_jobs or 0,
        },
    }


@router.get("/vulnerability-trends")
async def vulnerability_trends(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Vulnerability count trend over time (last N days)."""
    since = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=days)
    result = await db.execute(
        select(
            func.date(Vulnerability.created_at).label("date"),
            func.count(Vulnerability.vulnerability_id).label("count"),
        )
        .where(Vulnerability.created_at >= since)
        .group_by(func.date(Vulnerability.created_at))
        .order_by(func.date(Vulnerability.created_at))
    )
    return [{"date": str(row.date), "count": row.count} for row in result.all()]


@router.get("/risk-distribution")
async def risk_distribution(
    db: AsyncSession = Depends(get_db),
) -> Dict[str, int]:
    """Distribution of vulnerabilities by risk level."""
    result = await db.execute(
        select(
            func.floor(Vulnerability.calculated_risk_score).label("risk_bucket"),
            func.count(Vulnerability.vulnerability_id).label("count"),
        ).group_by(func.floor(Vulnerability.calculated_risk_score))
    )
    return {f"{int(row.risk_bucket)}": row.count for row in result.all()}


@router.get("/patch-job-trends")
async def patch_job_trends(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Patch job execution trend over time."""
    since = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=days)
    result = await db.execute(
        select(
            func.date(PatchJob.completed_at).label("date"),
            PatchJob.status,
            func.count(PatchJob.job_id).label("count"),
        )
        .where(PatchJob.completed_at >= since)
        .group_by(func.date(PatchJob.completed_at), PatchJob.status)
        .order_by(func.date(PatchJob.completed_at))
    )
    return [
        {"date": str(row.date), "status": row.status, "count": row.count} for row in result.all()
    ]


@router.get("/top-assets-by-risk")
async def top_assets_by_risk(
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Top assets by aggregate risk score."""
    result = await db.execute(
        select(
            Asset.hostname,
            Asset.asset_id,
            func.sum(Vulnerability.calculated_risk_score).label("total_risk"),
            func.count(Vulnerability.vulnerability_id).label("vuln_count"),
        )
        .join(Vulnerability, Asset.asset_id == Vulnerability.asset_id)
        .where(Vulnerability.status == "OPEN")
        .group_by(Asset.asset_id, Asset.hostname)
        .order_by(func.sum(Vulnerability.calculated_risk_score).desc())
        .limit(limit)
    )
    return [
        {
            "asset_id": str(row.asset_id),
            "hostname": row.hostname,
            "total_risk": float(row.total_risk or 0),
            "vuln_count": row.vuln_count,
        }
        for row in result.all()
    ]


@router.get("/audit/verify")
async def audit_verify(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Verify audit chain integrity."""
    return await AuditLedger.verify_chain(db)


@router.get("/audit/recent")
async def recent_audit_events(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Recent audit events."""
    result = await db.execute(select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit))
    return [
        {
            "event_id": str(e.event_id),
            "actor": e.actor,
            "action": e.action,
            "payload": e.payload,
            "timestamp": e.timestamp.isoformat() if e.timestamp else None,
            "event_hash": e.event_hash[:16] + "...",
        }
        for e in result.scalars().all()
    ]
