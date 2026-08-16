import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


class NotificationChannel(ABC):
    """Abstract notification channel."""

    @abstractmethod
    async def send(
        self,
        title: str,
        message: str,
        payload: Dict[str, Any] = None,
        level: str = "info",
    ) -> bool:
        pass


class WebhookNotifier(NotificationChannel):
    """Generic webhook notifier (Slack, Teams, custom)."""

    def __init__(self, webhook_url: str, template: str = None) -> None:
        self.webhook_url = webhook_url
        self.template = template or '{{"text": "{title}: {message}"}}'

    async def send(
        self,
        title: str,
        message: str,
        payload: Dict[str, Any] = None,
        level: str = "info",
    ) -> bool:
        try:
            content = self.template.format(
                title=title,
                message=message,
                level=level,
                payload=json.dumps(payload or {}),
            )
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.webhook_url,
                    content=content,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
            logger.info("Webhook notification sent: %s", title)
            return True
        except Exception as exc:
            logger.error("Webhook notification failed: %s", exc)
            return False


class SlackNotifier(NotificationChannel):
    """Slack-specific notifier with block formatting."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send(
        self,
        title: str,
        message: str,
        payload: Dict[str, Any] = None,
        level: str = "info",
    ) -> bool:
        color_map = {
            "info": "#36a64f",
            "warning": "#ff9900",
            "error": "#ff0000",
            "critical": "#8b0000",
        }
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "text": {"type": "mrkdwn", "text": message}},
        ]
        if payload:
            blocks.append(
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{json.dumps(payload, indent=2)}```"},
                }
            )
        message_json = {
            "attachments": [{"color": color_map.get(level, "#36a64f"), "blocks": blocks}]
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.webhook_url,
                    json=message_json,
                    headers={"Content-Type": "application/json"},
                )
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False


class TeamsNotifier(NotificationChannel):
    """Microsoft Teams Adaptive Card notifier."""

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send(
        self,
        title: str,
        message: str,
        payload: Dict[str, Any] = None,
        level: str = "info",
    ) -> bool:
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.5",
                        "body": [
                            {
                                "type": "TextBlock",
                                "text": title,
                                "weight": "Bolder",
                                "size": "Medium",
                            },
                            {"type": "TextBlock", "text": message, "wrap": True},
                        ],
                        "msteams": {"width": "Full"},
                    },
                }
            ],
        }
        if payload:
            card["attachments"][0]["content"]["body"].append(
                {
                    "type": "TextBlock",
                    "text": f"```{json.dumps(payload, indent=2)}```",
                    "fontFamily": "Monospace",
                }
            )
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(
                    self.webhook_url, json=card, headers={"Content-Type": "application/json"}
                )
                resp.raise_for_status()
            return True
        except Exception as exc:
            logger.error("Teams notification failed: %s", exc)
            return False


class NotificationService:
    """Manages multiple notification channels."""

    def __init__(self) -> None:
        self.channels: Dict[str, NotificationChannel] = {}

    def register(self, name: str, channel: NotificationChannel) -> None:
        self.channels[name] = channel

    async def notify(
        self,
        title: str,
        message: str,
        payload: Dict[str, Any] = None,
        level: str = "info",
        channels: Optional[list] = None,
    ) -> Dict[str, bool]:
        """Send notification to specified channels (or all if None)."""
        targets = channels or list(self.channels.keys())
        results = {}
        for name in targets:
            channel = self.channels.get(name)
            if channel:
                results[name] = await channel.send(title, message, payload, level)
            else:
                results[name] = False
        return results


# Module-level service instance
_notification_service: NotificationService | None = None


def get_notification_service() -> NotificationService:
    global _notification_service
    if _notification_service is None:
        _notification_service = NotificationService()
    return _notification_service


async def notify_plan_approval(
    plan_id: str,
    asset_hostname: str,
    decision: str,
    approver: str,
) -> None:
    """Convenience function for plan approval notifications."""
    service = get_notification_service()
    await service.notify(
        title=f"Remediation Plan {decision}",
        message=f"Plan {plan_id} for {asset_hostname} was {decision.lower()} by {approver}",
        payload={
            "plan_id": plan_id,
            "asset": asset_hostname,
            "approver": approver,
            "decision": decision,
        },
        level="info" if decision == "APPROVED" else "warning",
    )


async def notify_patch_execution(
    job_id: str,
    plan_id: str,
    asset_hostname: str,
    status: str,
    actions_count: int,
) -> None:
    """Convenience function for patch execution notifications."""
    service = get_notification_service()
    await service.notify(
        title=f"Patch Job {status}",
        message=(
            f"Job {job_id} (plan {plan_id}) on {asset_hostname} "
            f"finished with {status} ({actions_count} actions)"
        ),
        payload={
            "job_id": job_id,
            "plan_id": plan_id,
            "asset": asset_hostname,
            "status": status,
            "actions": actions_count,
        },
        level="info" if status == "SUCCESS" else "error",
    )


async def notify_critical_vulnerability(
    asset_hostname: str,
    cve_id: str,
    package: str,
    risk_score: float,
) -> None:
    """Convenience function for critical vulnerability alerts."""
    service = get_notification_service()
    await service.notify(
        title="Critical Vulnerability Detected",
        message=f"{cve_id} in {package} on {asset_hostname} (risk: {risk_score})",
        payload={"asset": asset_hostname, "cve": cve_id, "package": package, "risk": risk_score},
        level="critical",
    )
