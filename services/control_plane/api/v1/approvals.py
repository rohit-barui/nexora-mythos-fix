from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.core.db import get_db
from services.models.db_models import Approval, RemediationPlan
from services.models.domain_schemas import ApprovalCreate, ApprovalResponse

router = APIRouter(prefix="/approvals", tags=["Approvals"])


@router.post("", response_model=ApprovalResponse)
async def submit_approval(approval_in: ApprovalCreate, db: AsyncSession = Depends(get_db)):
    plan = await db.get(RemediationPlan, approval_in.plan_id)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation Plan not found")

    approval = Approval(**approval_in.model_dump())
    db.add(approval)

    if approval_in.decision == "APPROVED":
        plan.status = "APPROVED"
    else:
        plan.status = "REJECTED_BY_HUMAN"

    await db.commit()
    await db.refresh(approval)
    return approval


@router.get("", response_model=List[ApprovalResponse])
async def list_approvals(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Approval))
    return result.scalars().all()
