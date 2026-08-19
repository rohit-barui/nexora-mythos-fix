import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit.ledger import AuditLedger
from services.control_plane.core.db import get_db
from services.control_plane.core.security import verify_hmac_signature_json
from services.models.db_models import Approval, RemediationPlan
from services.models.domain_schemas import ApprovalCreate, ApprovalResponse

router = APIRouter(prefix="/approvals", tags=["Approvals"])


class ApprovalCallback(BaseModel):
    plan_id: str
    decision: str
    approver: str
    channel: str
    signature: Optional[str] = None
    comments: Optional[str] = None


@router.post("/callback", response_model=ApprovalResponse)
async def approval_callback(
    payload: ApprovalCallback,
    x_nexora_signature: Optional[str] = Header(None, alias="X-Nexora-Signature"),
    db: AsyncSession = Depends(get_db),
):
    """HMAC-verified webhook callback for MS Teams / Outlook approval actions."""
    # Cards sign exactly {plan_id, decision, approver, channel}; exclude optional
    # fields from verification to keep signer/verifier canonical JSON identical.
    body = payload.model_dump(exclude={"signature", "comments"})
    signature = payload.signature or x_nexora_signature or ""
    if not verify_hmac_signature_json(body, signature):
        raise HTTPException(status_code=401, detail="Invalid HMAC signature")

    if payload.decision not in ("APPROVED", "REJECTED", "MODIFIED"):
        raise HTTPException(status_code=400, detail="Invalid decision")

    try:
        plan_uuid = uuid.UUID(payload.plan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid plan_id")

    plan = await db.get(RemediationPlan, plan_uuid)
    if not plan:
        raise HTTPException(status_code=404, detail="Remediation Plan not found")

    approval = Approval(
        plan_id=plan.plan_id,
        approver=payload.approver,
        decision=payload.decision,
        comments=payload.comments,
        channel=payload.channel,
    )
    db.add(approval)
    plan.status = "APPROVED" if payload.decision == "APPROVED" else "REJECTED_BY_HUMAN"

    await db.commit()
    await db.refresh(approval)

    await AuditLedger.log_event(
        db,
        actor=payload.approver,
        action="APPROVAL_DECISION",
        payload={
            "approval_id": str(approval.approval_id),
            "plan_id": payload.plan_id,
            "decision": payload.decision,
            "channel": payload.channel,
            "signature_verified": True,
        },
    )
    return approval


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

    await AuditLedger.log_event(
        db,
        actor=approval_in.approver,
        action="APPROVAL_DECISION",
        payload={
            "approval_id": str(approval.approval_id),
            "plan_id": str(plan.plan_id),
            "decision": approval_in.decision,
            "channel": approval_in.channel,
        },
    )
    return approval


@router.get("", response_model=List[ApprovalResponse])
async def list_approvals(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Approval))
    return result.scalars().all()
