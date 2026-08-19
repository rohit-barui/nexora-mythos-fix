"""
Jira Cloud REST API bi-directional connector (Blueprint Pillar 11).

Auto-creates a Jira Security Issue when a vulnerability risk is critical and
resolves the ticket once the vulnerability is verified closed. Persists the
mapping in the itsm_tickets table for bi-directional status sync.
"""

import base64
import logging
import uuid
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from services.models.db_models import ITSMTicket

logger = logging.getLogger(__name__)


class JiraConnector:
    """Client for the Jira Cloud REST API."""

    def __init__(self, base_url: str, email: str, api_token: str, timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.email = email
        self.api_token = api_token
        self.timeout = timeout

    @property
    def headers(self) -> Dict[str, str]:
        credentials = f"{self.email}:{self.api_token}"
        return {
            "Authorization": f"Basic {base64.b64encode(credentials.encode()).decode()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def create_security_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Security Issue",
        priority: str = "Highest",
    ) -> Dict[str, Any]:
        """Create a Jira security issue and return the created issue key/URL."""
        body = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": priority},
            }
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue", json=body, headers=self.headers
            )
            resp.raise_for_status()
            data = resp.json()
        return {
            "key": data.get("key"),
            "id": data.get("id"),
            "url": f"{self.base_url}/browse/{data.get('key')}",
        }

    async def get_issue(self, issue_key: str) -> Dict[str, Any]:
        """Fetch the current state of a Jira issue."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/rest/api/2/issue/{issue_key}", headers=self.headers
            )
            resp.raise_for_status()
            return resp.json()

    async def resolve_issue(self, issue_key: str, transition_id: str = "21") -> bool:
        """Transition a Jira issue to Done (default transition id 21)."""
        body = {"transition": {"id": transition_id}}
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/rest/api/2/issue/{issue_key}/transitions",
                json=body,
                headers=self.headers,
            )
            if resp.status_code == 204:
                return True
            resp.raise_for_status()
            return True

    async def get_issue_status(self, issue_key: str) -> Optional[str]:
        """Return the current status name of a Jira issue."""
        data = await self.get_issue(issue_key)
        return data.get("fields", {}).get("status", {}).get("name")


async def sync_jira_ticket(
    db: AsyncSession,
    connector: JiraConnector,
    vulnerability_id: uuid.UUID,
    project_key: str,
    cve_id: str,
    asset_hostname: str,
    risk_score: float,
) -> ITSMTicket:
    """Create a Jira issue and persist an ITSMTicket record for the vulnerability."""
    issue = await connector.create_security_issue(
        project_key=project_key,
        summary=f"[Nexora] Critical vulnerability {cve_id} on {asset_hostname}",
        description=(
            f"Nexora detected critical vulnerability {cve_id} on {asset_hostname} "
            f"(risk score {risk_score}/10). Automatic remediation pending approval."
        ),
        priority="Highest" if risk_score >= 9.0 else "High",
    )
    ticket = ITSMTicket(
        vulnerability_id=vulnerability_id,
        system_name="JIRA",
        external_ticket_id=issue["key"],
        ticket_url=issue["url"],
        status="OPEN",
    )
    db.add(ticket)
    await db.commit()
    await db.refresh(ticket)
    logger.info("Jira ticket %s created for %s", issue["key"], cve_id)
    return ticket
