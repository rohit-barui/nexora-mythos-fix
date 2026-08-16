from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from services.integrations.notifier import (
    NotificationService,
    SlackNotifier,
    TeamsNotifier,
    WebhookNotifier,
    get_notification_service,
)

router = APIRouter(prefix="/notifications", tags=["Notifications"])


class WebhookConfig(BaseModel):
    name: str = Field(..., description="Unique name for this webhook")
    webhook_url: str = Field(..., description="Target webhook URL")
    template: Optional[str] = Field(None, description="Optional Jinja2-like template")
    enabled: bool = True


class SlackConfig(BaseModel):
    name: str
    webhook_url: str
    enabled: bool = True


class TeamsConfig(BaseModel):
    name: str
    webhook_url: str
    enabled: bool = True


class TestNotificationRequest(BaseModel):
    title: str = "Test Notification"
    message: str = "This is a test notification from Nexora"
    level: str = Field("info", pattern="^(info|warning|error|critical)$")
    channels: Optional[List[str]] = None


class WebhookConfigResponse(WebhookConfig):
    type: str = "webhook"


class SlackConfigResponse(SlackConfig):
    type: str = "slack"


class TeamsConfigResponse(TeamsConfig):
    type: str = "teams"


# In-memory config store (replace with DB in production)
_notification_configs: Dict[str, Dict[str, Any]] = {}


def _get_service() -> NotificationService:
    """Get or create notification service with registered channels."""
    service = get_notification_service()
    # Register configured channels
    for name, config in _notification_configs.items():
        if name not in service.channels:
            if config["type"] == "webhook":
                service.register(
                    name, WebhookNotifier(config["webhook_url"], config.get("template"))
                )
            elif config["type"] == "slack":
                service.register(name, SlackNotifier(config["webhook_url"]))
            elif config["type"] == "teams":
                service.register(name, TeamsNotifier(config["webhook_url"]))
    return service


@router.post("/webhooks", response_model=WebhookConfigResponse, status_code=201)
async def register_webhook(config: WebhookConfig):
    if config.name in _notification_configs:
        raise HTTPException(status_code=409, detail="Webhook name already exists")
    _notification_configs[config.name] = {
        "type": "webhook",
        "webhook_url": config.webhook_url,
        "template": config.template,
        "enabled": config.enabled,
    }
    _get_service()  # re-register
    return WebhookConfigResponse(**config.model_dump())


@router.post("/slack", response_model=SlackConfigResponse, status_code=201)
async def register_slack(config: SlackConfig):
    if config.name in _notification_configs:
        raise HTTPException(status_code=409, detail="Slack config name already exists")
    _notification_configs[config.name] = {
        "type": "slack",
        "webhook_url": config.webhook_url,
        "enabled": config.enabled,
    }
    _get_service()
    return SlackConfigResponse(**config.model_dump())


@router.post("/teams", response_model=TeamsConfigResponse, status_code=201)
async def register_teams(config: TeamsConfig):
    if config.name in _notification_configs:
        raise HTTPException(status_code=409, detail="Teams config name already exists")
    _notification_configs[config.name] = {
        "type": "teams",
        "webhook_url": config.webhook_url,
        "enabled": config.enabled,
    }
    _get_service()
    return TeamsConfigResponse(**config.model_dump())


@router.get("/configs")
async def list_notification_configs() -> List[Dict[str, Any]]:
    return [
        {
            "name": name,
            "type": cfg["type"],
            "webhook_url": cfg["webhook_url"],
            "enabled": cfg.get("enabled", True),
        }
        for name, cfg in _notification_configs.items()
    ]


@router.delete("/configs/{name}")
async def delete_notification_config(name: str):
    if name not in _notification_configs:
        raise HTTPException(status_code=404, detail="Configuration not found")
    del _notification_configs[name]
    service = get_notification_service()
    if name in service.channels:
        del service.channels[name]
    return {"message": "Deleted"}


@router.post("/test")
async def send_test_notification(request: TestNotificationRequest) -> Dict[str, Any]:
    service = _get_service()
    results = await service.notify(
        title=request.title,
        message=request.message,
        level=request.level,
        channels=request.channels,
    )
    return {"results": results}
