import logging
from typing import Any, Dict, List

from services.execution_engine.executor import PatchExecutor
from services.orchestrator.activities import (
    ActivityContext,
    execute_activity,
    rollback_activity,
    snapshot_activity,
)
from services.orchestrator.canary import CanaryDeployment, Redlock

logger = logging.getLogger(__name__)


class OrchestrationEngine:
    """
    In-process deterministic orchestration engine.
    Mirrors the Temporal remediation workflow (snapshot -> execute -> verify ->
    rollback -> result) so the full pipeline runs and is testable end-to-end
    without a Temporal server. Detects Temporal availability for future upgrades.
    """

    def __init__(self, executor: PatchExecutor = None) -> None:
        self.executor = executor or PatchExecutor()

    async def run_remediation(
        self,
        host: str,
        os_type: str,
        actions: List[Dict[str, Any]],
        credentials: Dict[str, Any] = None,
        canary_rings: bool = False,
        available_hosts: List[str] = None,
        lock_ttl_seconds: int = 300,
    ) -> Dict[str, Any]:
        credentials = credentials or {}
        lock_name = f"nexora:lock:{host}"
        lock = Redlock(lock_name, ttl_seconds=lock_ttl_seconds)

        if not lock.acquire():
            return {
                "overall_status": "BLOCKED",
                "host": host,
                "action_count": len(actions),
                "actions": [],
                "snapshot_summary": {},
                "blocked_by": lock_name,
            }

        try:
            return await self._run_locked(
                host,
                os_type,
                actions,
                credentials,
                canary_rings=canary_rings,
                available_hosts=available_hosts or [host],
            )
        finally:
            lock.release()

    async def _run_locked(
        self,
        host: str,
        os_type: str,
        actions: List[Dict[str, Any]],
        credentials: Dict[str, Any],
        canary_rings: bool,
        available_hosts: List[str],
    ) -> Dict[str, Any]:
        context = ActivityContext(
            host=host,
            os_type=os_type,
            actions=actions,
            credentials=credentials,
        )

        if canary_rings:
            deployment = CanaryDeployment(len(available_hosts), available_hosts)
            ring = deployment.next_ring(0)
            return {
                "overall_status": "CANARY",
                "host": host,
                "action_count": len(actions),
                "actions": [],
                "snapshot_summary": {},
                "canary": ring,
            }

        snapshot_result = await snapshot_activity(context)
        logger.info(
            "Orchestration: %s snapshots created for %s", len(snapshot_result["snapshots"]), host
        )

        execution = await execute_activity(context)

        if execution["overall_status"] == "ROLLED_BACK":
            rollbacks = await rollback_activity(context, execution)
            execution["rollbacks"] = rollbacks

        execution["snapshot_summary"] = {
            "snapshot_ids": [s["snapshot_id"] for s in snapshot_result["snapshots"]]
        }
        return execution
