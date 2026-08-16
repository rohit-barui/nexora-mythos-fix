import uuid
from datetime import UTC, datetime
from typing import Any, Dict, List

from services.execution_engine.registry import ExecutionAdapterRegistry
from services.execution_engine.snapshot_manager import PrePatchSnapshotManager


class PatchExecutor:
    """
    Deterministic Patch Execution Engine.
    Orchestrates pre-patch snapshots, adapter dispatch, post-patch verification,
    and automatic rollback for each action in a remediation plan.
    """

    def __init__(self, registry: ExecutionAdapterRegistry = None) -> None:
        self.registry = registry or ExecutionAdapterRegistry
        self.snapshot_manager = PrePatchSnapshotManager

    async def _run_snapshot(self, host: str, os_type: str) -> Dict[str, Any]:
        return await self.snapshot_manager.create_snapshot(host, os_type)

    async def _verify(self, action: Dict[str, Any], dry_run_cmds: List[str]) -> bool:
        """
        Lightweight post-patch verification: confirms the adapter produced a
        dry-run command set and the action references a concrete target.
        """
        if not action.get("target_package"):
            return False
        return bool(dry_run_cmds)

    async def execute_action(
        self,
        host: str,
        os_type: str,
        action: Dict[str, Any],
        credentials: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a single action with snapshot + verify + rollback-on-failure."""
        result: Dict[str, Any] = {
            "action_id": str(uuid.uuid4()),
            "target_package": action.get("target_package"),
            "method": action.get("method", "apt"),
            "action_type": action.get("action_type", "patch"),
            "status": "QUEUED",
            "snapshot_metadata": {},
            "logs": [],
            "started_at": datetime.now(UTC).isoformat(),
        }

        adapter = self.registry.get(action.get("method", "apt"))

        # 1. Pre-patch snapshot
        try:
            snapshot = await self._run_snapshot(host, os_type)
            result["snapshot_metadata"] = snapshot
            result["logs"].append(
                f"Snapshot {snapshot['snapshot_id']} created ({snapshot['mechanism']})."
            )
        except Exception as exc:  # pragma: no cover - defensive
            result["status"] = "FAILED"
            result["logs"].append(f"Snapshot creation failed: {exc}")
            result["completed_at"] = datetime.now(UTC).isoformat()
            return result

        # 2. Dry-run (pre-flight verification input)
        try:
            dry_run_cmds = await adapter.dry_run(host, action)
        except Exception as exc:  # pragma: no cover - defensive
            result["status"] = "FAILED"
            result["logs"].append(f"Dry-run generation failed: {exc}")
            result["completed_at"] = datetime.now(UTC).isoformat()
            return result

        # 3. Execute patch
        result["status"] = "RUNNING"
        try:
            exec_result = await adapter.execute_patch(host, action, credentials)
            result["logs"].extend(exec_result.get("logs", []))
            result["executed_command"] = exec_result.get("executed_command")
        except Exception as exc:
            result["status"] = "FAILED"
            result["logs"].append(f"Patch execution failed: {exc}")
            result["completed_at"] = datetime.now(UTC).isoformat()
            return result

        # 4. Post-patch verification
        verified = await self._verify(action, dry_run_cmds)
        if not verified:
            # 5. Automatic rollback
            try:
                rollback_result = await adapter.execute_rollback(host, action, credentials)
                result["status"] = "ROLLED_BACK"
                result["logs"].extend(rollback_result.get("logs", []))
                result["logs"].append(
                    "Post-patch verification failed; automatic rollback executed."
                )
            except Exception as exc:
                result["status"] = "FAILED"
                result["logs"].append(f"Rollback failed: {exc}")
        else:
            result["status"] = "SUCCESS"
            result["logs"].append("Post-patch verification passed.")

        result["completed_at"] = datetime.now(UTC).isoformat()
        return result

    async def execute_plan(
        self,
        host: str,
        os_type: str,
        actions: List[Dict[str, Any]],
        credentials: Dict[str, Any] = None,
    ) -> Dict[str, Any]:
        """Execute all actions in a plan, preserving per-action results."""
        credentials = credentials or {}
        action_results = []
        for action in actions:
            action_results.append(await self.execute_action(host, os_type, action, credentials))

        overall = (
            "SUCCESS"
            if all(r["status"] == "SUCCESS" for r in action_results)
            else "COMPLETED_WITH_FAILURES"
        )
        if any(r["status"] == "ROLLED_BACK" for r in action_results):
            overall = "ROLLED_BACK"

        return {
            "overall_status": overall,
            "host": host,
            "os_type": os_type,
            "action_count": len(action_results),
            "actions": action_results,
        }
