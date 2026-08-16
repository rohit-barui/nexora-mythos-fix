import re
from typing import Any, Dict, List

from pydantic import ValidationError

from services.llm_planner.config import LLMPlannerLimits
from services.models.domain_schemas import RemediationPlanSchema


class CognitiveAIFirewall:
    """
    Cognitive AI Firewall & Sanitizer.
    Inspects input vulnerability metadata for injection attempts and validates structured
    LLM output payloads against Pydantic v2 schemas before passing to OPA Policy Engine.
    """

    SUSPICIOUS_PATTERNS = [
        r"ignore previous instructions",
        r"system prompt",
        r"sudo rm",
        r"chmod 777",
        r"curl http",
        r"bash -i",
        r"exec\(",
        r"eval\(",
        r"__import__",
    ]

    # Dangerous characters that must never appear in package names or versions
    FORBIDDEN_CHARS = [";", "&", "|", "`", "$", "\n", "\r"]

    # Whitelist for safe package names: alphanumerics, . _ - + : / @ and spaces
    PACKAGE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._+\-/:@ ]+$")

    @classmethod
    def sanitize_input_context(cls, context_text: str) -> str:
        """
        Sanitize input context text passed to LLMs.
        """
        sanitized = context_text
        for pattern in cls.SUSPICIOUS_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED_ATTEMPT]", sanitized, flags=re.IGNORECASE)
        return sanitized

    @classmethod
    def sanitize_plan_payload(cls, raw_llm_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strip disallowed keys and redact suspicious strings from an LLM payload
        before schema validation. Returns a cleaned copy of the payload.
        """
        cleaned: Dict[str, Any] = {}
        allowed_top_keys = {"actions", "estimated_risk_after_patch", "explanation"}
        allowed_action_keys = {
            "action_type",
            "target_package",
            "method",
            "target_version",
            "restart_required",
            "rollback_command_template",
            "pre_patch_checks",
        }

        for key, value in raw_llm_json.items():
            if key not in allowed_top_keys:
                continue
            if key == "actions" and isinstance(value, list):
                cleaned_actions = []
                for action in value:
                    if not isinstance(action, dict):
                        continue
                    cleaned_action = {k: v for k, v in action.items() if k in allowed_action_keys}
                    for field in ("target_package", "target_version", "rollback_command_template"):
                        if field in cleaned_action and isinstance(cleaned_action[field], str):
                            cleaned_action[field] = cls.sanitize_input_context(
                                cleaned_action[field]
                            )
                    cleaned_actions.append(cleaned_action)
                cleaned[key] = cleaned_actions
            elif isinstance(value, str):
                cleaned[key] = cls.sanitize_input_context(value)
            else:
                cleaned[key] = value

        return cleaned

    @classmethod
    def validate_plan_schema(cls, raw_llm_json: Dict[str, Any]) -> RemediationPlanSchema:
        """
        Strictly validates LLM JSON output against Pydantic schema.
        Raises ValueError if plan contains unvalidated or malformed actions.
        """
        sanitized_json = cls.sanitize_plan_payload(raw_llm_json)
        try:
            plan = RemediationPlanSchema.model_validate(sanitized_json)
            # Extra safety check: verify no action attempts shell injection strings
            for action in plan.actions:
                cls._validate_action_fields(action)
            return plan
        except ValidationError as e:
            raise ValueError(f"AI Firewall Rejected LLM Output: Schema validation failed: {str(e)}")

    @classmethod
    def _validate_action_fields(cls, action: Any) -> None:
        for field in ("target_package", "target_version", "rollback_command_template"):
            value = getattr(action, field, None)
            if not isinstance(value, str) or not value:
                continue
            if any(char in value for char in cls.FORBIDDEN_CHARS):
                raise ValueError(
                    "Malicious character detected in target package name: "
                    f"{action.target_package}"
                )
        if not cls.PACKAGE_NAME_PATTERN.match(action.target_package):
            raise ValueError(
                "Invalid target package name (not on safe whitelist): " f"{action.target_package}"
            )

    @classmethod
    def check_plan_plausibility(
        cls,
        plan: RemediationPlanSchema,
        vulnerabilities: List[Dict[str, Any]],
        limits: LLMPlannerLimits | None = None,
    ) -> None:
        """
        Detect LLM drift / hallucination: actions must reference packages that were
        present in the input vulnerability context. Raises ValueError if the plan
        drifts beyond the configured bounds.
        """
        limits = limits or LLMPlannerLimits()
        known_packages = {v.get("package_name") for v in vulnerabilities if v.get("package_name")}

        if not plan.actions:
            raise ValueError("AI Firewall Rejected LLM Output: plan has no actions")

        total = len(plan.actions)
        drifted = 0
        for action in plan.actions:
            # Patch actions must reference a known package; virtual patches may target URLs/paths
            if action.action_type == "patch" and action.target_package not in known_packages:
                drifted += 1

        drift_percent = (drifted / total) * 100.0
        hallucination_score = drifted / total

        if drift_percent > limits.max_drift_percent:
            raise ValueError(
                "AI Firewall blocked plan: drift exceeded configured bound "
                f"({drift_percent:.1f}% > {limits.max_drift_percent}%). "
                "LLM referenced packages not present in vulnerability context."
            )
        if hallucination_score > limits.max_hallucination_score:
            raise ValueError(
                "AI Firewall blocked plan: hallucination score exceeded configured bound "
                f"({hallucination_score:.2f} > {limits.max_hallucination_score})."
            )
