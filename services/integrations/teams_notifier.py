"""
Microsoft Teams Adaptive Card approval notifier (Blueprint Pillar 5).

Posts an Adaptive Card v1.4 message via webhook with vulnerability risk
details, affected asset, remediation commands, and interactive Approve /
Reject buttons. Each button embeds an HMAC-signed payload that the control
plane approval callback verifies before applying the decision.
"""

import logging
from typing import Any, Dict, List, Optional

import httpx

from services.control_plane.core.security import compute_hmac_signature_json

logger = logging.getLogger(__name__)


class TeamsApprovalNotifier:
    """Sends interactive remediation approval requests to Microsoft Teams."""

    def __init__(self, webhook_url: str, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url
        self.timeout = timeout

    def _signed_action_data(
        self,
        plan_id: str,
        decision: str,
        signing_secret: str,
        approver: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload = {
            "plan_id": plan_id,
            "decision": decision,
            "approver": approver or "teams-user",
            "channel": "TEAMS_BOT",
        }
        payload["signature"] = compute_hmac_signature_json(payload, signing_secret)
        return payload

    def build_approval_card(
        self,
        plan_id: str,
        hostname: str,
        cve_id: str,
        risk_score: float,
        commands: List[str],
        signing_secret: str,
        approver: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Build an Adaptive Card v1.4 with Approve / Reject actions."""
        return {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": "Remediation Plan Approval Required",
                                "weight": "Bolder",
                                "size": "Medium",
                            },
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Plan ID", "value": plan_id},
                                    {"title": "Asset", "value": hostname},
                                    {"title": "CVE", "value": cve_id},
                                    {"title": "Risk Score", "value": f"{risk_score}/10"},
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": "Commands to execute:\n"
                                + "\n".join(f"`{c}`" for c in commands),
                                "wrap": True,
                            },
                            {
                                "type": "TextBlock",
                                "text": "Review the remediation plan and select an action:",
                                "wrap": True,
                            },
                        ],
                        "actions": [
                            {
                                "type": "Action.Submit",
                                "title": "Approve",
                                "style": "positive",
                                "data": self._signed_action_data(
                                    plan_id, "APPROVED", signing_secret, approver
                                ),
                            },
                            {
                                "type": "Action.Submit",
                                "title": "Reject",
                                "style": "destructive",
                                "data": self._signed_action_data(
                                    plan_id, "REJECTED", signing_secret, approver
                                ),
                            },
                        ],
                    },
                }
            ],
        }

    async def send_approval_request(
        self,
        plan_id: str,
        hostname: str,
        cve_id: str,
        risk_score: float,
        commands: List[str],
        signing_secret: str,
        approver: Optional[str] = None,
    ) -> bool:
        """Post an approval card to the configured Teams webhook."""
        card = self.build_approval_card(
            plan_id=plan_id,
            hostname=hostname,
            cve_id=cve_id,
            risk_score=risk_score,
            commands=commands,
            signing_secret=signing_secret,
            approver=approver,
        )
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(
                    self.webhook_url, json=card, headers={"Content-Type": "application/json"}
                )
                resp.raise_for_status()
            logger.info("Teams approval card sent for plan %s", plan_id)
            return True
        except Exception as exc:
            logger.error("Teams approval card failed: %s", exc)
            return False


def build_approval_card(
    plan_id: str,
    hostname: str,
    cve_id: str,
    risk_score: float,
    commands: List[str],
    signing_secret: str,
    approver: Optional[str] = None,
) -> Dict[str, Any]:
    """Module-level convenience factory."""
    notifier = TeamsApprovalNotifier(webhook_url="unused")
    return notifier.build_approval_card(
        plan_id=plan_id,
        hostname=hostname,
        cve_id=cve_id,
        risk_score=risk_score,
        commands=commands,
        signing_secret=signing_secret,
        approver=approver,
    )
