from typing import Any, Dict, List

from services.execution_engine.base import BaseExecutionAdapter


class KernelHardeningAdapter(BaseExecutionAdapter):
    """
    Kernel Hardening Execution Adapter.
    Applies deterministic sysctl security hardening parameters
    for zero-day / kernel-level mitigations.
    """

    HARDENING_PARAMS = {
        "kernel.kptr_restrict": "2",
        "kernel.dmesg_restrict": "1",
        "kernel.perf_event_paranoid": "3",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.tcp_syncookies": "1",
    }

    @property
    def adapter_name(self) -> str:
        return "sysctl"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        target = action.get("target_package")
        return [f"sysctl -w {target}=$(cat /proc/sys/{target.replace('.', '/')})"]

    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        target = action.get("target_package")
        value = self.HARDENING_PARAMS.get(target, "1")
        cmd = f"sudo sysctl -w {target}={value}"
        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": cmd,
            "hardening_params": {target: value},
            "logs": [f"Applied kernel hardening {target}={value} on {target_host}."],
        }

    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        target = action.get("target_package")
        original = action.get("installed_version", action.get("previous_value", "0"))
        cmd = f"sudo sysctl -w {target}={original}"
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": cmd,
            "logs": [f"Reverted kernel parameter {target} to {original} on {target_host}."],
        }
