"""
AI Activity & Token/Cost Telemetry (Blueprint Pillar 14).

Persists an AIActivityLogRecord for every LLM prompt, computes estimated USD
cost, and exposes aggregation helpers used by the /api/v1/ai/stats and
/api/v1/ai/logs endpoints.
"""

import hashlib
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from services.llm_planner.providers import estimate_llm_cost
from services.models.db_models import AIActivityLog


def compute_prompt_hash(prompt_text: str) -> str:
    """SHA-256 of the sanitized prompt text (blueprint Pillar 14)."""
    return hashlib.sha256(prompt_text.encode("utf-8")).hexdigest()


async def record_ai_activity(
    db: AsyncSession,
    provider: str,
    model: str,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    latency_ms: float = 0.0,
    sanitizer_passed: bool = True,
    prompt_text: Optional[str] = None,
    vulnerability_id: Optional[str] = None,
) -> AIActivityLog:
    """Persist a single AI activity log entry with computed cost."""
    total_tokens = prompt_tokens + completion_tokens
    log = AIActivityLog(
        vulnerability_id=vulnerability_id,
        provider=provider,
        model=model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=estimate_llm_cost(prompt_tokens, completion_tokens),
        latency_ms=latency_ms,
        sanitizer_passed=sanitizer_passed,
        prompt_hash=compute_prompt_hash(prompt_text) if prompt_text else None,
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


async def get_ai_telemetry_stats(db: AsyncSession) -> Dict[str, Any]:
    """
    Aggregate AI telemetry:
      - total prompts, total tokens, total estimated cost
      - tokens & cost grouped by provider and by model
      - average latency
    """
    total_prompts = (await db.execute(select(func.count(AIActivityLog.log_id)))).scalar_one()
    total_prompt_tokens = (
        await db.execute(select(func.coalesce(func.sum(AIActivityLog.prompt_tokens), 0)))
    ).scalar_one()
    total_completion_tokens = (
        await db.execute(select(func.coalesce(func.sum(AIActivityLog.completion_tokens), 0)))
    ).scalar_one()
    total_cost = (
        await db.execute(select(func.coalesce(func.sum(AIActivityLog.estimated_cost_usd), 0.0)))
    ).scalar_one()
    avg_latency = (
        await db.execute(select(func.coalesce(func.avg(AIActivityLog.latency_ms), 0.0)))
    ).scalar_one()

    provider_rows = (
        await db.execute(
            select(
                AIActivityLog.provider,
                func.count(AIActivityLog.log_id),
                func.sum(AIActivityLog.total_tokens),
                func.sum(AIActivityLog.estimated_cost_usd),
            ).group_by(AIActivityLog.provider)
        )
    ).all()
    model_rows = (
        await db.execute(
            select(
                AIActivityLog.model,
                func.count(AIActivityLog.log_id),
                func.sum(AIActivityLog.total_tokens),
                func.sum(AIActivityLog.estimated_cost_usd),
            ).group_by(AIActivityLog.model)
        )
    ).all()

    return {
        "total_prompts": int(total_prompts),
        "total_prompt_tokens": int(total_prompt_tokens),
        "total_completion_tokens": int(total_completion_tokens),
        "total_tokens": int(total_prompt_tokens) + int(total_completion_tokens),
        "total_estimated_cost_usd": round(float(total_cost), 6),
        "avg_latency_ms": round(float(avg_latency), 2),
        "by_provider": [
            {
                "provider": row[0],
                "prompts": int(row[1]),
                "tokens": int(row[2] or 0),
                "cost_usd": round(float(row[3] or 0.0), 6),
            }
            for row in provider_rows
        ],
        "by_model": [
            {
                "model": row[0],
                "prompts": int(row[1]),
                "tokens": int(row[2] or 0),
                "cost_usd": round(float(row[3] or 0.0), 6),
            }
            for row in model_rows
        ],
    }


async def list_ai_activity_logs(
    db: AsyncSession, limit: int = 50, offset: int = 0
) -> List[AIActivityLog]:
    """Return a paginated list of AI activity log entries."""
    result = await db.execute(
        select(AIActivityLog).order_by(AIActivityLog.timestamp.desc()).limit(limit).offset(offset)
    )
    return list(result.scalars().all())
