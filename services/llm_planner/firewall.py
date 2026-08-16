import re
from typing import Any, Dict

from pydantic import ValidationError

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
    def validate_plan_schema(cls, raw_llm_json: Dict[str, Any]) -> RemediationPlanSchema:
        """
        Strictly validates LLM JSON output against Pydantic schema.
        Raises ValueError if plan contains unvalidated or malformed actions.
        """
        try:
            plan = RemediationPlanSchema.model_validate(raw_llm_json)
            # Extra safety check: verify no action attempts shell injection strings
            for action in plan.actions:
                if any(char in action.target_package for char in [";", "&", "|", "`", "$"]):
                    raise ValueError(
                        "Malicious character detected in target package name: "
                        f"{action.target_package}"
                    )
            return plan
        except ValidationError as e:
            raise ValueError(f"AI Firewall Rejected LLM Output: Schema validation failed: {str(e)}")
