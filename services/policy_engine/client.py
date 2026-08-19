import datetime
import json
from pathlib import Path
from typing import Any, Dict, List

import httpx

from services.observability.metrics import record_opa_evaluation


class OPAPolicyClient:
    """
    Client for Open Policy Agent (OPA) Server REST API.
    Evaluates remediation plans against authoritative Rego rules.
    """

    REGO_DIR = Path(__file__).resolve().parents[2] / "policies"

    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url.rstrip("/")

    @classmethod
    def load_rego_policies(cls) -> List[Path]:
        """
        Return the list of Rego policy files shipped with the platform.
        Raises FileNotFoundError if the policies directory is missing.
        """
        if not cls.REGO_DIR.is_dir():
            raise FileNotFoundError(f"Rego policies directory not found: {cls.REGO_DIR}")
        rego_files = sorted(cls.REGO_DIR.glob("*.rego"))
        if not rego_files:
            raise FileNotFoundError(f"No .rego policy files found in {cls.REGO_DIR}")
        return rego_files

    @classmethod
    def _rego_policy_content(cls) -> str:
        """Concatenate all Rego policy files for inspection/validation purposes."""
        return "\n".join(p.read_text(encoding="utf-8") for p in cls.load_rego_policies())

    async def evaluate_plan(
        self,
        asset_info: Dict[str, Any],
        plan_payload: Dict[str, Any],
        has_escalation_approval: bool = False,
    ) -> Dict[str, Any]:
        current_hour = datetime.datetime.now(datetime.UTC).hour

        input_data = {
            "input": {
                "asset": asset_info,
                "plan": plan_payload,
                "current_hour_utc": current_hour,
                "has_escalation_approval": has_escalation_approval,
            }
        }

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{self.opa_url}/v1/data/nexora/remediation", json=input_data
                )
                if response.status_code == 200:
                    result = response.json().get("result", {})
                    allowed = result.get("allow", False)
                    record_opa_evaluation("allowed" if allowed else "denied")
                    return {
                        "allowed": allowed,
                        "require_escalation": result.get("require_escalation", False),
                        "violations": result.get("violations", []),
                        "evaluated_at": datetime.datetime.now(datetime.UTC).isoformat(),
                    }
        except Exception:
            pass

        # Fallback local evaluation mirroring the Rego rules when OPA is unreachable
        return self._evaluate_locally(
            asset_info, plan_payload, has_escalation_approval, current_hour
        )

    def _evaluate_locally(
        self,
        asset_info: Dict[str, Any],
        plan_payload: Dict[str, Any],
        has_escalation_approval: bool,
        current_hour: int,
    ) -> Dict[str, Any]:
        """Local mirror of policies/remediation_rules.rego."""
        violations: List[str] = []
        actions = plan_payload.get("actions", [])

        if asset_info.get("environment") == "production" and (9 <= current_hour <= 17):
            violations.append(
                "Production patching blocked during UTC business hours (09:00 - 17:00)"
            )

        criticality = int(asset_info.get("criticality_score", 5))
        if criticality >= 8:
            for action in actions:
                if action.get("restart_required") is True and not has_escalation_approval:
                    violations.append(
                        "Actions requiring restart on critical assets must undergo "
                        "approval escalation"
                    )

        for action in actions:
            if not action.get("target_package"):
                violations.append("Invalid action definition: missing target_package or method")

        allowed = len(violations) == 0
        require_escalated = criticality >= 9 or any(
            a.get("target_package") == "linux-image-generic" for a in actions
        )

        record_opa_evaluation("allowed" if allowed else "denied")
        return {
            "allowed": allowed,
            "require_escalation": require_escalated,
            "violations": violations,
            "evaluated_at": datetime.datetime.now(datetime.UTC).isoformat(),
            "mode": "local_fallback",
        }

    @classmethod
    def validate_rego_syntax_structure(cls) -> Dict[str, Any]:
        """
        Lightweight structural validation of the shipped Rego files:
        verifies package declarations and required rule names exist.
        """
        content = cls._rego_policy_content()
        required_packages = {"nexora.remediation"}
        required_rules = {"allow", "violations", "require_escalation"}

        missing_packages = [p for p in required_packages if f"package {p}" not in content]
        missing_rules = []
        for rule in required_rules:
            if not any(
                line.strip().startswith(f"{rule}[") or line.strip().startswith(f"{rule} ")
                for line in content.splitlines()
            ):
                missing_rules.append(rule)

        return {
            "files": [p.name for p in cls.load_rego_policies()],
            "missing_packages": missing_packages,
            "missing_rules": missing_rules,
            "valid": not missing_packages and not missing_rules,
            "policy_content": content,
        }

    @classmethod
    def plan_payload_to_json(cls, plan_payload: Dict[str, Any]) -> str:
        """Serialize a plan payload to sorted JSON (for OPA input fidelity checks)."""
        return json.dumps(plan_payload, sort_keys=True)
