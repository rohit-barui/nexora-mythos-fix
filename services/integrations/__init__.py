"""
Nexora Integrations — Notification Channels (Webhook, Slack, Teams)
"""

from services.integrations.notifier import (
    NotificationChannel,
    NotificationService,
    SlackNotifier,
    TeamsNotifier,
    WebhookNotifier,
    get_notification_service,
    notify_critical_vulnerability,
    notify_patch_execution,
    notify_plan_approval,
)

__all__ = [
    "NotificationChannel",
    "NotificationService",
    "SlackNotifier",
    "TeamsNotifier",
    "WebhookNotifier",
    "get_notification_service",
    "notify_plan_approval",
    "notify_patch_execution",
    "notify_critical_vulnerability",
]
