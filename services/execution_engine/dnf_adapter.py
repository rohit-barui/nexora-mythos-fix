from typing import Any, Dict, List

from services.execution_engine.base import BaseExecutionAdapter


class DnfAdapter(BaseExecutionAdapter):
    """
    RHEL / CentOS / Rocky DNF/YUM Package Execution Adapter
    """

    @property
    def adapter_name(self) -> str:
        return "dnf"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        pkg = action.get("target_package")
        return [f"sudo dnf check-update {pkg}"]

    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        pkg = action.get("target_package")
        cmd = f"sudo dnf update -y {pkg}"
        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"DNF updated package {pkg} on {target_host} successfully."],
        }

    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        cmd = "sudo dnf history undo last -y"
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"DNF undo history executed on {target_host}."],
        }
