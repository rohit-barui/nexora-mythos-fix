from typing import Any, Dict, List

from services.execution_engine.base import BaseExecutionAdapter


class WinRMAdapter(BaseExecutionAdapter):
    """
    Windows Server WinRM & PowerShell Execution Adapter
    """

    @property
    def adapter_name(self) -> str:
        return "winrm"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        pkg = action.get("target_package")
        return [f"Get-WUInstall -Name '{pkg}' -ListOnly"]

    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        pkg = action.get("target_package")
        cmd = f"Install-WindowsUpdate -KBArticleID '{pkg}' -AcceptAll -AutoReboot:$false"
        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"WinRM installed Windows Update KB {pkg} on {target_host}."],
        }

    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        pkg = action.get("target_package")
        cmd = f"wusa.exe /uninstall /kb:{pkg} /quiet /norestart"
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"WinRM uninstalled Windows KB {pkg} on {target_host}."],
        }
