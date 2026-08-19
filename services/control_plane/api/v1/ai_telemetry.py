from typing import Any, Dict, List

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.core.db import get_db
from services.llm_planner.telemetry import get_ai_telemetry_stats, list_ai_activity_logs

router = APIRouter(prefix="/ai", tags=["AI Telemetry"])


@router.get("/stats")
async def ai_stats(db: AsyncSession = Depends(get_db)) -> Dict[str, Any]:
    """Aggregate AI token usage, latency & cost metrics."""
    return await get_ai_telemetry_stats(db)


@router.get("/logs")
async def ai_logs(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
) -> List[Dict[str, Any]]:
    """Query paginated AI prompt/response activity log."""
    logs = await list_ai_activity_logs(db, limit=limit, offset=offset)
    return [
        {
            "log_id": str(log.log_id),
            "vulnerability_id": log.vulnerability_id,
            "provider": log.provider,
            "model": log.model,
            "prompt_tokens": log.prompt_tokens,
            "completion_tokens": log.completion_tokens,
            "total_tokens": log.total_tokens,
            "estimated_cost_usd": log.estimated_cost_usd,
            "latency_ms": log.latency_ms,
            "sanitizer_passed": log.sanitizer_passed,
            "prompt_hash": log.prompt_hash,
            "timestamp": log.timestamp,
        }
        for log in logs
    ]
