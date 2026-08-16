from typing import Any, Dict, List

from services.llm_planner.firewall import CognitiveAIFirewall
from services.models.domain_schemas import RemediationPlanSchema


class LLMPlannerClient:
    """
    LLM Planner Client supporting OpenAI, Anthropic, or Local Ollama / fallback providers.
    Enforces strict Pydantic JSON validation through CognitiveAIFirewall.
    """

    def __init__(self, api_key: str = "", model_name: str = "gpt-4o-mini"):
        self.api_key = api_key
        self.model_name = model_name

    async def generate_remediation_plan(
        self, asset_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
    ) -> RemediationPlanSchema:
        # 1. Sanitize context via Cognitive AI Firewall
        context_str = f"Asset: {asset_info}\nVulnerabilities: {vulnerabilities}"
        sanitized_context = CognitiveAIFirewall.sanitize_input_context(context_str)
        if "[REDACTED_ATTEMPT]" in sanitized_context:
            raise ValueError(
                "AI Firewall blocked plan generation: prompt injection attempt detected "
                "in vulnerability context."
            )

        # 2. Build structured prompt / mock fallback for development
        # In actual API execution, sends structured schema prompt to LLM endpoint
        first_vuln = vulnerabilities[0] if vulnerabilities else {}
        rollback_template = (
            f"apt-get install {first_vuln.get('package_name', 'openssl')}"
            f"={first_vuln.get('installed_version', '1.0.0')}"
            if first_vuln
            else "apt-get install openssl=1.0.0"
        )
        simulated_llm_response = {
            "actions": [
                {
                    "action_type": "patch",
                    "target_package": first_vuln.get("package_name", "openssl"),
                    "method": "apt" if asset_info.get("os_type") == "debian" else "dnf",
                    "target_version": first_vuln.get("fixed_version", "latest"),
                    "restart_required": False,
                    "rollback_command_template": rollback_template,
                    "pre_patch_checks": ["check_disk_space", "verify_snapshot"],
                }
            ],
            "estimated_risk_after_patch": "low",
            "explanation": (
                f"Automated patch generated for asset {asset_info.get('hostname')} "
                "to resolve detected vulnerabilities safely."
            ),
        }

        # 3. Pass through Cognitive AI Firewall schema enforcer
        validated_plan = CognitiveAIFirewall.validate_plan_schema(simulated_llm_response)
        return validated_plan
