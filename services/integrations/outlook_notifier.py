"""
Microsoft Outlook Actionable Messages approval notifier (Blueprint Pillar 5).

Sends an Actionable Email containing an embedded
`<script type="application/adaptivecard+json">` payload with interactive
Approve / Reject buttons so security leads can review and approve directly
inside Outlook desktop/web clients. The payload is HMAC-signed so the
control plane callback can verify authenticity.
"""

import base64
import json
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any, List, Optional

from services.control_plane.core.security import compute_hmac_signature_json

logger = logging.getLogger(__name__)


class OutlookApprovalNotifier:
    """Sends Actionable Message approval requests to Microsoft Outlook."""

    def __init__(
        self,
        smtp_host: str = "smtp.office365.com",
        smtp_port: int = 587,
        smtp_username: str = "",
        smtp_password: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_password = smtp_password
        self.timeout = timeout

    def build_actionable_email(
        self,
        plan_id: str,
        hostname: str,
        cve_id: str,
        risk_score: float,
        commands: List[str],
        signing_secret: str,
        recipient: str,
        sender: str,
        approver: Optional[str] = None,
    ) -> EmailMessage:
        """Build an Actionable Message email with an embedded Adaptive Card."""
        approve_data = {
            "plan_id": plan_id,
            "decision": "APPROVED",
            "approver": approver or recipient,
            "channel": "OUTLOOK",
        }
        approve_data["signature"] = compute_hmac_signature_json(approve_data, signing_secret)

        reject_data = {
            "plan_id": plan_id,
            "decision": "REJECTED",
            "approver": approver or recipient,
            "channel": "OUTLOOK",
        }
        reject_data["signature"] = compute_hmac_signature_json(reject_data, signing_secret)

        card_json = json.dumps(
            {
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
                        "text": "Commands:\n" + "\n".join(f"`{c}`" for c in commands),
                        "wrap": True,
                    },
                ],
                "actions": [
                    {
                        "type": "Action.Submit",
                        "title": "Approve",
                        "style": "positive",
                        "data": approve_data,
                    },
                    {
                        "type": "Action.Submit",
                        "title": "Reject",
                        "style": "destructive",
                        "data": reject_data,
                    },
                ],
            }
        )
        script_tag = (
            '<script type="application/adaptivecard+json">'
            + base64.b64encode(card_json.encode("utf-8")).decode("ascii")
            + "</script>"
        )

        msg = EmailMessage()
        msg["Subject"] = f"[Nexora] Approval Required: Remediation Plan {plan_id}"
        msg["From"] = sender
        msg["To"] = recipient
        msg["X-Application-Id"] = "nexora-control-plane"
        msg.set_content(
            f"Remediation plan {plan_id} for {hostname} ({cve_id}, risk {risk_score}/10) "
            "requires approval. Open this message in Outlook to review and respond.",
            subtype="plain",
        )
        msg.add_alternative(
            f"<html><body>{script_tag}<p>Remediation plan approval request.</p></body></html>",
            subtype="html",
        )
        return msg

    async def send_approval_request(
        self,
        plan_id: str,
        hostname: str,
        cve_id: str,
        risk_score: float,
        commands: List[str],
        signing_secret: str,
        recipient: str,
        sender: Optional[str] = None,
        approver: Optional[str] = None,
    ) -> bool:
        """Send the Actionable Message via SMTP."""
        sender = sender or self.smtp_username
        if not sender:
            logger.error("Outlook sender not configured")
            return False
        msg = self.build_actionable_email(
            plan_id=plan_id,
            hostname=hostname,
            cve_id=cve_id,
            risk_score=risk_score,
            commands=commands,
            signing_secret=signing_secret,
            recipient=recipient,
            sender=sender,
            approver=approver,
        )
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                server.starttls(context=context)
                if self.smtp_username and self.smtp_password:
                    server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            logger.info("Outlook Actionable Message sent for plan %s", plan_id)
            return True
        except Exception as exc:
            logger.error("Outlook Actionable Message failed: %s", exc)
            return False


def build_actionable_email(
    plan_id: str,
    hostname: str,
    cve_id: str,
    risk_score: float,
    commands: List[str],
    signing_secret: str,
    recipient: str,
    sender: str,
) -> Any:
    """Module-level convenience factory returning an EmailMessage."""
    notifier = OutlookApprovalNotifier()
    return notifier.build_actionable_email(
        plan_id=plan_id,
        hostname=hostname,
        cve_id=cve_id,
        risk_score=risk_score,
        commands=commands,
        signing_secret=signing_secret,
        recipient=recipient,
        sender=sender,
    )
