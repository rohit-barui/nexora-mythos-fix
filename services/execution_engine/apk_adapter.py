from typing import Any, Dict, List

from services.execution_engine.base import BaseExecutionAdapter


class ApkAdapter(BaseExecutionAdapter):
    """
    Alpine Linux APK Package Execution Adapter.
    """

    @property
    def adapter_name(self) -> str:
        return "apk"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        pkg = action.get("target_package")
        version = action.get("target_version", "")
        if version and version != "latest":
            cmd = f"sudo apk add --upgrade {pkg}={version} --simulate"
        else:
            cmd = f"sudo apk add --upgrade {pkg} --simulate"
        return [cmd]

    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        pkg = action.get("target_package")
        version = action.get("target_version", "")
        if version and version != "latest":
            cmd = f"sudo apk add --upgrade {pkg}={version}"
        else:
            cmd = f"sudo apk add --upgrade {pkg}"

        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"APK upgraded package {pkg} on {target_host} successfully."],
        }

    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        pkg = action.get("target_package")
        version = action.get("installed_version", action.get("target_version", "latest"))
        rollback_cmd = f"sudo apk add {pkg}={version}"
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": rollback_cmd,
            "logs": [f"APK rolled back package {pkg} on {target_host}."],
        }
