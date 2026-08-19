"""
Canonical LLM plan schema & JSON-schema helpers (Blueprint Pillar 3).

Re-exports the Pydantic v2 RemediationPlanSchema used to enforce bounded,
structured LLM output, and provides JSON-schema generation used when building
provider prompts so every provider in the failover chain returns conformant JSON.
"""

import json
from typing import Any, Dict

from pydantic import TypeAdapter

from services.models.domain_schemas import ActionDefinition, RemediationPlanSchema

__all__ = ["ActionDefinition", "RemediationPlanSchema", "remediation_plan_json_schema"]


_remediation_plan_adapter: TypeAdapter = TypeAdapter(RemediationPlanSchema)


def remediation_plan_json_schema() -> Dict[str, Any]:
    """Return the JSON Schema of RemediationPlanSchema (for provider prompts)."""
    return _remediation_plan_adapter.json_schema()


def remediation_plan_json_schema_str() -> str:
    """Return a compact JSON-schema string for embedding in provider prompts."""
    return json.dumps(remediation_plan_json_schema(), indent=2)


def validate_remediation_plan_json(raw: Dict[str, Any]) -> RemediationPlanSchema:
    """Validate and coerce a raw dict into a RemediationPlanSchema."""
    return _remediation_plan_adapter.validate_python(raw)
