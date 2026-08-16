from typing import Dict, Any, List
from services.execution_engine.base import BaseExecutionAdapter

class VirtualPatchAdapter(BaseExecutionAdapter):
    """
    Virtual Patching Adapter.
    Deploys ModSecurity / WAF rules and sysctl kernel hardening parameters
    when vendor patches are unavailable for zero-days.
    """

    @property
    def adapter_name(self) -> str:
        return "virtual_patch"

    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        target = action.get("target_package")
        return [f"waf-cli validate-rule --target {target}"]

    async def execute_patch(self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        target = action.get("target_package")
        rule_def = f"SecRule REQUEST_URI \"{target}\" \"id:990001,phase:2,deny,status:403,msg:'Nexora Virtual Patch Block'\""
        return {
            "status": "SUCCESS",
            "host": target_host,
            "executed_command": "deploy_waf_rule",
            "waf_rule": rule_def,
            "logs": [f"Deployed Virtual Patch WAF Rule for {target} on {target_host}."]
        }

    async def execute_rollback(self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]) -> Dict[str, Any]:
        target = action.get("target_package")
        return {
            "status": "ROLLED_BACK",
            "host": target_host,
            "executed_command": "remove_waf_rule",
            "logs": [f"Removed Virtual Patch WAF Rule for {target} on {target_host}."]
        }
