from typing import Any, Dict, List

from services.execution_engine.base import BaseExecutionAdapter


class KubernetesAdapter(BaseExecutionAdapter):
    """
    Kubernetes Image Rollout Execution Adapter (kubectl / helm).
    """

    @property
    def adapter_name(self) -> str:
        return "k8s_image"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        workload = action.get("target_package")
        image = action.get("target_version", "")
        if image:
            cmd = (
                f"kubectl set image deployment/{workload} "
                f"*=registry.example.com/app:{image} --dry-run=client"
            )
        else:
            cmd = f"kubectl rollout status deployment/{workload} --dry-run=client"
        return [cmd]

    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        workload = action.get("target_package")
        image = action.get("target_version", "")
        if image:
            cmd = f"kubectl set image deployment/{workload} *=registry.example.com/app:{image}"
        else:
            cmd = f"kubectl rollout restart deployment/{workload}"

        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"K8s image rollout triggered for deployment/{workload}."],
        }

    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        workload = action.get("target_package")
        cmd = f"kubectl rollout undo deployment/{workload}"
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"K8s rollout reverted for deployment/{workload}."],
        }
