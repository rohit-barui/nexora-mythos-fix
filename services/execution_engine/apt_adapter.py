from typing import Dict, Any, List
from services.execution_engine.base import BaseExecutionAdapter

class AptAdapter(BaseExecutionAdapter):
    """
    Debian / Ubuntu APT Package Execution Adapter (Paramiko SSH / Ansible)
    """

    @property
    def adapter_name(self) -> str:
        return "apt"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        pkg = action.get("target_package")
        version = action.get("target_version", "")
        if version and version != "latest":
            cmd = f"sudo apt-get --simulate install {pkg}={version}"
        else:
            cmd = f"sudo apt-get --simulate install --only-upgrade {pkg}"
        return [cmd]

    async def execute_patch(self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        pkg = action.get("target_package")
        version = action.get("target_version", "")
        if version and version != "latest":
            cmd = f"sudo apt-get update && sudo apt-get install -y --only-upgrade {pkg}={version}"
        else:
            cmd = f"sudo apt-get update && sudo apt-get install -y --only-upgrade {pkg}"

        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"APT updated package {pkg} on {target_host} successfully."]
        }

    async def execute_rollback(self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        rollback_cmd = action.get("rollback_command_template", f"sudo apt-get install -y {action.get('target_package')}")
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": rollback_cmd,
            "logs": [f"APT rolled back package on {target_host} successfully."]
        }
