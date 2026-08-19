"""
ServiceNow Table API bi-directional connector (Blueprint Pillar 11).

Auto-creates a ServiceNow Change Request (change_request table) for patch
execution approval and updates its state based on patch job outcomes.
Persists the mapping in the itsm_tickets table.
"""

import base64
import logging
import uuid
from typing import Any, Dict

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from services.models.db_models import ITSMTicket

logger = logging.getLogger(__name__)


class ServiceNowConnector:
    """Client for the ServiceNow Table API."""

    def __init__(
        self, instance_url: str, username: str, password: str, timeout: float = 15.0
    ) -> None:
        self.instance_url = instance_url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout

    @property
    def headers(self) -> Dict[str, str]:
        credentials = f"{self.username}:{self.password}"
        return {
            "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def create_change_request(
        self,
        short_description: str,
        description: str,
        change_type: str = "standard",
        risk: str = "medium",
    ) -> Dict[str, Any]:
        """Create a Change Request (CHG) and return its sys_id and number."""
        body = {
            "short_description": short_description,
            "description": description,
            "type": change_type,
            "risk": risk,
            "assignment_group": "Change Management",
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.instance_url}/api/now/table/change_request",
                json=body,
                headers=self.headers,
            )
            resp.raise_for_status()
            data = resp.json().get("result", {})
        return {
            "sys_id": data.get("sys_id"),
            "number": data.get("number"),
            "state": data.get("state"),
            "url": (
                f"{self.instance_url}/nav_to.do?uri=change_request.do?"
                f"sys_id={data.get('sys_id')}"
            ),
        }

    async def get_change_request(self, sys_id: str) -> Dict[str, Any]:
        """Fetch the current state of a Change Request."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.instance_url}/api/now/table/change_request/{sys_id}",
                headers=self.headers,
            )
            resp.raise_for_status()
            return resp.json().get("result", {})

    async def update_change_request(self, sys_id: str, state: str) -> bool:
        """Update the state of a Change Request (e.g. closed, cancelled)."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.patch(
                f"{self.instance_url}/api/now/table/change_request/{sys_id}",
                json={"state": state},
                headers=self.headers,
            )
            resp.raise_for_status()
            return True


async def sync_servicenow_change_request(
    db: AsyncSession,
    connector: ServiceNowConnector,
    vulnerability_id: uuid.UUID,
    cve_id: str,
    asset_hostname: str,
    plan_id: str,
) -> ITSMTicket:
    """Create a ServiceNow Change Request and persist an ITSMTicket record."""
    chg = await connector.create_change_request(
        short_description=f"Patch execution for {cve_id} on {asset_hostname}",
        description=(
            f"Nexora remediation plan {plan_id} will patch {cve_id} on {asset_hostname}. "
            "Change approval required before execution."
        ),
    )
    ticket = ITSMTicket(
        vulnerability_id=vulnerability_id,
        system_name="SERVICENOW",
        external_ticket_id=chg["number"],
        ticket_url=chg["url"],
        status="OPEN",
    )
    db.add(ticket)
    await db.commit()
    await db.refresh(ticket)
    logger.info("ServiceNow Change Request %s created for %s", chg["number"], cve_id)
    return ticket
