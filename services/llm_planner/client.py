import json
from typing import Any, Dict, List

import httpx

from services.llm_planner.config import LLMPlannerLimits
from services.llm_planner.firewall import CognitiveAIFirewall
from services.llm_planner.prompts import REMEDIATION_PLANNER_SYSTEM_PROMPT
from services.models.domain_schemas import RemediationPlanSchema

OPENAI_CHAT_URL = "https://api.openai.com/v1/chat/completions"


class LLMPlannerClient:
    """
    LLM Planner Client supporting OpenAI (real API) and a deterministic mock fallback.
    Enforces bounded guardrails via CognitiveAIFirewall and LLMPlannerLimits.
    """

    def __init__(
        self,
        api_key: str = "",
        model_name: str = "",
        limits: LLMPlannerLimits | None = None,
    ):
        self.api_key = api_key
        self.limits = limits or LLMPlannerLimits()
        self.model_name = model_name or self.limits.model

    async def generate_remediation_plan(
        self, asset_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
    ) -> RemediationPlanSchema:
        if not vulnerabilities:
            raise ValueError(
                "AI Firewall blocked plan generation: no vulnerabilities provided in context."
            )

        # 1. Sanitize context via Cognitive AI Firewall
        context_str = f"Asset: {asset_info}\nVulnerabilities: {vulnerabilities}"
        sanitized_context = CognitiveAIFirewall.sanitize_input_context(context_str)
        if "[REDACTED_ATTEMPT]" in sanitized_context:
            raise ValueError(
                "AI Firewall blocked plan generation: prompt injection attempt detected "
                "in vulnerability context."
            )

        # 2. Produce raw plan JSON from the provider (real API or deterministic mock)
        if self.api_key:
            raw_plan = await self._call_openai(sanitized_context)
        else:
            raw_plan = self._mock_plan(asset_info, vulnerabilities)

        # 3. Enforce the full Cognitive AI Firewall pipeline
        validated_plan = CognitiveAIFirewall.validate_plan_schema(raw_plan)
        CognitiveAIFirewall.check_plan_plausibility(
            validated_plan, vulnerabilities, limits=self.limits
        )
        return validated_plan

    def _build_user_prompt(self, context: str) -> str:
        return (
            "Analyze the following asset and vulnerability context and return ONLY a JSON "
            "object matching this schema:\n"
            "{\n"
            '  "actions": [\n'
            "    {\n"
            '      "action_type": "patch|virtual_patch|service_reload|kernel_hardening|rollback",\n'
            '      "target_package": "<package name>",\n'
            '      "method": "apt|dnf|apk|winrm|k8s_image|waf_rule|sysctl",\n'
            '      "target_version": "<fixed version or latest>",\n'
            '      "restart_required": false,\n'
            '      "rollback_command_template": "<rollback command template>",\n'
            '      "pre_patch_checks": ["check_disk_space", "verify_snapshot"]\n'
            "    }\n"
            "  ],\n"
            '  "estimated_risk_after_patch": "low|medium|high",\n'
            '  "explanation": "<justification>"\n'
            "}\n\n"
            f"Context:\n{context}"
        )

    async def _call_openai(self, sanitized_context: str) -> Dict[str, Any]:
        """
        Call OpenAI chat completions with structured JSON output enforced.
        """
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": REMEDIATION_PLANNER_SYSTEM_PROMPT},
                {"role": "user", "content": self._build_user_prompt(sanitized_context)},
            ],
            "response_format": {"type": "json_object"},
            "max_tokens": self.limits.max_response_tokens,
            "temperature": 0.0,
        }

        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(OPENAI_CHAT_URL, headers=headers, json=body)
            response.raise_for_status()
            data = response.json()
            content = data["choices"][0]["message"]["content"]
            return json.loads(content)

    def _mock_plan(
        self, asset_info: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Deterministic mock plan used when no API key is configured (offline/test mode)."""
        first_vuln = vulnerabilities[0] if vulnerabilities else {}
        rollback_template = (
            f"apt-get install {first_vuln.get('package_name', 'openssl')}"
            f"={first_vuln.get('installed_version', '1.0.0')}"
            if first_vuln
            else "apt-get install openssl=1.0.0"
        )
        return {
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
