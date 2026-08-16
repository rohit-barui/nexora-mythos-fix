from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.audit.ledger import AuditLedger
from services.control_plane.core.db import get_db
from services.models.db_models import AuditEvent
from services.models.domain_schemas import AuditEventResponse

router = APIRouter(prefix="/audit", tags=["Audit Log"])


@router.get("", response_model=List[AuditEventResponse])
async def list_audit_events(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(AuditEvent).order_by(desc(AuditEvent.timestamp)))
    return result.scalars().all()


@router.post("/log", response_model=AuditEventResponse)
async def log_audit_event(
    actor: str, action: str, payload: dict, db: AsyncSession = Depends(get_db)
):
    return await AuditLedger.log_event(db, actor=actor, action=action, payload=payload)


@router.get("/verify")
async def verify_audit_chain(db: AsyncSession = Depends(get_db)):
    return await AuditLedger.verify_chain(db)
