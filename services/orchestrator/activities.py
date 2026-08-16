from dataclasses import dataclass
from typing import Any, Dict, List

from temporalio import activity

from services.execution_engine.executor import PatchExecutor
from services.execution_engine.snapshot_manager import PrePatchSnapshotManager


def _safe_heartbeat(message: str) -> None:
    """Heartbeat is a no-op when running outside a Temporal activity context."""
    try:
        activity.heartbeat(message)
    except RuntimeError:
        pass


# Module-level executor for testability (can be patched)
_executor: PatchExecutor | None = None


def _get_executor() -> PatchExecutor:
    global _executor
    if _executor is None:
        _executor = PatchExecutor()
    return _executor


def set_executor(executor: PatchExecutor | None) -> None:
    """Replace the module-level executor (for testing)."""
    global _executor
    _executor = executor


@dataclass
class ActivityContext:
    """Serializable context passed between Temporal activities."""

    host: str
    os_type: str
    actions: List[Dict[str, Any]]
    credentials: Dict[str, Any]


async def snapshot_activity(context: ActivityContext) -> Dict[str, Any]:
    """Temporal activity: create a pre-patch snapshot."""
    _safe_heartbeat("creating snapshot")
    snapshots = []
    for _ in context.actions:
        snapshots.append(
            await PrePatchSnapshotManager.create_snapshot(context.host, context.os_type)
        )
    return {"host": context.host, "snapshots": snapshots}


async def execute_activity(context: ActivityContext) -> Dict[str, Any]:
    """Temporal activity: run the deterministic patch executor over all actions."""
    _safe_heartbeat("executing patch actions")
    executor = _get_executor()
    return await executor.execute_plan(
        host=context.host,
        os_type=context.os_type,
        actions=context.actions,
        credentials=context.credentials,
    )


async def rollback_activity(
    context: ActivityContext, execution_result: Dict[str, Any]
) -> Dict[str, Any]:
    """Temporal activity: roll back any failed / unverified actions."""
    _safe_heartbeat("rolling back failed actions")
    executor = _get_executor()
    rollbacks = []
    for idx, action_result in enumerate(execution_result.get("actions", [])):
        if action_result.get("status") not in ("SUCCESS",):
            action = context.actions[idx]
            adapter = executor.registry.get(action.get("method", "apt"))
            rollbacks.append(
                await adapter.execute_rollback(context.host, action, context.credentials)
            )
    return {"rollbacks": rollbacks}
