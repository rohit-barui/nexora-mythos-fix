import datetime
from typing import Any, Dict

import httpx


class OPAPolicyClient:
    """
    Client for Open Policy Agent (OPA) Server REST API.
    Evaluates remediation plans against authoritative Rego rules.
    """

    def __init__(self, opa_url: str = "http://localhost:8181"):
        self.opa_url = opa_url.rstrip("/")

    async def evaluate_plan(
        self,
        asset_info: Dict[str, Any],
        plan_payload: Dict[str, Any],
        has_escalation_approval: bool = False,
    ) -> Dict[str, Any]:
        current_hour = datetime.datetime.utcnow().hour

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
                    return {
                        "allowed": result.get("allow", False),
                        "require_escalation": result.get("require_escalation", False),
                        "violations": result.get("violations", []),
                        "evaluated_at": datetime.datetime.utcnow().isoformat(),
                    }
        except Exception:
            pass

        # Fallback local evaluation if OPA service is unreachable during local testing
        violations = []
        if asset_info.get("environment") == "production" and (9 <= current_hour <= 17):
            violations.append(
                "Production patching blocked during UTC business hours (09:00 - 17:00)"
            )

        allowed = len(violations) == 0
        require_escalated = asset_info.get("criticality_score", 5) >= 9

        return {
            "allowed": allowed,
            "require_escalation": require_escalated,
            "violations": violations,
            "evaluated_at": datetime.datetime.utcnow().isoformat(),
            "mode": "local_fallback",
        }
