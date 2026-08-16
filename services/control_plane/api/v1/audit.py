import hashlib
import json
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

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
    # Fetch last audit event for Merkle tree hash chaining
    result = await db.execute(select(AuditEvent).order_by(desc(AuditEvent.timestamp)).limit(1))
    last_event = result.scalars().first()

    prev_hash = last_event.event_hash if last_event else "GENESIS_HASH"

    # Compute SHA-256 hash of payload + prev_hash
    payload_str = json.dumps(payload, sort_keys=True)
    combined = f"{actor}:{action}:{payload_str}:{prev_hash}"
    event_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()

    event = AuditEvent(
        actor=actor,
        action=action,
        payload=payload,
        previous_event_hash=prev_hash,
        event_hash=event_hash,
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event
