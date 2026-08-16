import hashlib
import json
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.models.db_models import AuditEvent

GENESIS_HASH = "GENESIS_HASH"


def compute_event_hash(actor: str, action: str, payload: Dict[str, Any], prev_hash: str) -> str:
    payload_str = json.dumps(payload, sort_keys=True)
    combined = f"{actor}:{action}:{payload_str}:{prev_hash}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


class AuditLedger:
    """
    Immutable Merkle-tree hash-chained audit ledger.
    Every event is linked to the previous event hash, enabling
    tamper-evident verification of the full history.
    """

    @staticmethod
    async def log_event(
        db: AsyncSession,
        actor: str,
        action: str,
        payload: Dict[str, Any],
    ) -> AuditEvent:
        result = await db.execute(select(AuditEvent).order_by(desc(AuditEvent.timestamp)).limit(1))
        last_event = result.scalars().first()
        prev_hash = last_event.event_hash if last_event else GENESIS_HASH

        event = AuditEvent(
            actor=actor,
            action=action,
            payload=payload,
            previous_event_hash=prev_hash,
            event_hash=compute_event_hash(actor, action, payload, prev_hash),
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)
        return event

    @staticmethod
    async def verify_chain(db: AsyncSession) -> Dict[str, Any]:
        """Walk the ledger and recompute hashes to detect tampering or gaps."""
        result = await db.execute(select(AuditEvent).order_by(AuditEvent.timestamp.asc()))
        events: List[AuditEvent] = list(result.scalars().all())

        issues: List[str] = []
        prev_hash = GENESIS_HASH
        for event in events:
            recomputed = compute_event_hash(event.actor, event.action, event.payload, prev_hash)
            if event.event_hash != recomputed:
                issues.append(
                    f"Hash mismatch at event {event.event_id}: "
                    f"expected {recomputed}, found {event.event_hash}"
                )
            if event.previous_event_hash != prev_hash:
                issues.append(
                    f"Chain broken at event {event.event_id}: "
                    f"previous hash {event.previous_event_hash} != {prev_hash}"
                )
            prev_hash = event.event_hash

        return {
            "valid": not issues,
            "event_count": len(events),
            "issues": issues,
        }

    @staticmethod
    async def last_event_hash(db: AsyncSession) -> Optional[str]:
        result = await db.execute(select(AuditEvent).order_by(desc(AuditEvent.timestamp)).limit(1))
        last_event = result.scalars().first()
        return last_event.event_hash if last_event else None
