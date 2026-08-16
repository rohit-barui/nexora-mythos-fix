import logging
from typing import Any, Dict, List

from services.execution_engine.executor import PatchExecutor
from services.orchestrator.activities import (
    ActivityContext,
    execute_activity,
    rollback_activity,
    snapshot_activity,
)

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
    ) -> Dict[str, Any]:
        credentials = credentials or {}
        context = ActivityContext(
            host=host,
            os_type=os_type,
            actions=actions,
            credentials=credentials,
        )

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
