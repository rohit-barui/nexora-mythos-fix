import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.control_plane.api.v1.approvals import ApprovalCallback, approval_callback
from services.control_plane.api.v1.patch_jobs import rollback_patch_job
from services.control_plane.core.security import compute_hmac_signature_json
from services.integrations.jira_connector import JiraConnector, sync_jira_ticket
from services.integrations.outlook_notifier import OutlookApprovalNotifier
from services.integrations.servicenow_connector import (
    ServiceNowConnector,
    sync_servicenow_change_request,
)
from services.integrations.teams_notifier import TeamsApprovalNotifier
from services.models.db_models import Asset, AuditEvent, Base, ITSMTicket, PatchJob, RemediationPlan
from services.models.domain_schemas import PatchJobResponse


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


async def _seed_asset_and_plan(db, *, status: str = "PENDING_APPROVAL"):
    asset = Asset(
        hostname="srv-1",
        os_type="debian",
        environment="production",
        criticality_score=8,
        exposure_level="internet-facing",
    )
    db.add(asset)
    await db.flush()
    plan = RemediationPlan(
        asset_id=asset.asset_id,
        vulnerability_ids=[],
        generated_by_llm=True,
        plan_payload={"actions": []},
        status=status,
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)
    return asset, plan


# --- Teams Approval Notifier ---


def test_teams_card_builds_adaptive_card():
    notifier = TeamsApprovalNotifier(webhook_url="https://webhook")
    card = notifier.build_approval_card(
        plan_id="plan-1",
        hostname="srv-1",
        cve_id="CVE-2026-0001",
        risk_score=9.2,
        commands=["apt-get update", "apt-get upgrade -y"],
        signing_secret="test-secret",
        approver="lead@corp.com",
    )
    content = card["attachments"][0]["content"]
    assert content["type"] == "AdaptiveCard"
    assert content["version"] == "1.4"
    titles = [a["title"] for a in content["actions"]]
    assert titles == ["Approve", "Reject"]

    approve_data = content["actions"][0]["data"]
    body = {k: v for k, v in approve_data.items() if k != "signature"}
    assert approve_data["decision"] == "APPROVED"
    assert approve_data["signature"] == compute_hmac_signature_json(body, "test-secret")


@pytest.mark.asyncio
async def test_teams_send_approval_request():
    notifier = TeamsApprovalNotifier(webhook_url="https://webhook")
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("services.integrations.teams_notifier.httpx.AsyncClient", return_value=mock_cm):
        result = await notifier.send_approval_request(
            plan_id="plan-1",
            hostname="srv-1",
            cve_id="CVE-2026-0001",
            risk_score=9.2,
            commands=["apt-get upgrade"],
            signing_secret="s",
        )
        assert result is True
        mock_client.post.assert_called_once()


# --- Outlook Actionable Messages ---


def test_outlook_email_embeds_actionable_payload():
    notifier = OutlookApprovalNotifier()
    msg = notifier.build_actionable_email(
        plan_id="plan-1",
        hostname="srv-1",
        cve_id="CVE-2026-0001",
        risk_score=8.7,
        commands=["dnf upgrade -y"],
        signing_secret="s",
        recipient="lead@corp.com",
        sender="nexora@corp.com",
    )
    html = msg.get_payload(1).get_content()
    assert "application/adaptivecard+json" in html
    assert msg["X-Application-Id"] == "nexora-control-plane"

    # Verify embedded card's approve data signature
    import base64

    card_b64 = html.split('adaptivecard+json">')[1].split("</script>")[0]
    card = json.loads(base64.b64decode(card_b64).decode("utf-8"))
    approve_data = card["actions"][0]["data"]
    body = {k: v for k, v in approve_data.items() if k != "signature"}
    assert approve_data["decision"] == "APPROVED"
    assert approve_data["signature"] == compute_hmac_signature_json(body, "s")


# --- Approval HMAC Callback ---


@pytest.mark.asyncio
async def test_approval_callback_valid_signature(db):
    asset, plan = await _seed_asset_and_plan(db)
    body = {
        "plan_id": str(plan.plan_id),
        "decision": "APPROVED",
        "approver": "lead@corp.com",
        "channel": "TEAMS_BOT",
    }
    body["signature"] = compute_hmac_signature_json(
        {k: v for k, v in body.items() if k != "signature"}
    )
    resp = await approval_callback(ApprovalCallback(**body), db=db)

    assert resp.decision == "APPROVED"
    assert (await db.get(RemediationPlan, plan.plan_id)).status == "APPROVED"

    audit = (await db.execute(select(AuditEvent))).scalars().first()
    assert audit.action == "APPROVAL_DECISION"


@pytest.mark.asyncio
async def test_approval_callback_invalid_signature(db):
    asset, plan = await _seed_asset_and_plan(db)
    from fastapi import HTTPException

    body = {
        "plan_id": str(plan.plan_id),
        "decision": "APPROVED",
        "approver": "lead@corp.com",
        "channel": "TEAMS_BOT",
        "signature": "deadbeef",
    }
    with pytest.raises(HTTPException) as exc:
        await approval_callback(ApprovalCallback(**body), db=db)
    assert exc.value.status_code == 401
    assert (await db.get(RemediationPlan, plan.plan_id)).status == "PENDING_APPROVAL"


# --- Jira Connector ---


def _jira_post_ok():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        return_value=MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"key": "SEC-1", "id": "10001"}),
        )
    )
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm, mock_client


@pytest.mark.asyncio
async def test_jira_create_security_issue(db):
    connector = JiraConnector("https://jira.example.com", "bot@corp.com", "token")
    mock_cm, mock_client = _jira_post_ok()
    with patch("services.integrations.jira_connector.httpx.AsyncClient", return_value=mock_cm):
        result = await connector.create_security_issue(
            project_key="SEC", summary="Critical", description="desc"
        )
    assert result["key"] == "SEC-1"
    assert result["url"] == "https://jira.example.com/browse/SEC-1"
    body = mock_client.post.call_args.kwargs["json"]
    assert body["fields"]["project"]["key"] == "SEC"


@pytest.mark.asyncio
async def test_jira_get_issue_status():
    connector = JiraConnector("https://jira.example.com", "bot@corp.com", "token")
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(
        return_value=MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"fields": {"status": {"name": "Done"}}}),
        )
    )
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    with patch("services.integrations.jira_connector.httpx.AsyncClient", return_value=mock_cm):
        status = await connector.get_issue_status("SEC-1")
    assert status == "Done"


@pytest.mark.asyncio
async def test_sync_jira_ticket_persists(db):
    connector = JiraConnector("https://jira.example.com", "bot@corp.com", "token")
    mock_cm, _ = _jira_post_ok()
    with patch("services.integrations.jira_connector.httpx.AsyncClient", return_value=mock_cm):
        ticket = await sync_jira_ticket(
            db,
            connector,
            vulnerability_id=uuid.uuid4(),
            project_key="SEC",
            cve_id="CVE-2026-0001",
            asset_hostname="srv-1",
            risk_score=9.5,
        )
    assert ticket.system_name == "JIRA"
    assert ticket.external_ticket_id == "SEC-1"
    assert (await db.get(ITSMTicket, ticket.ticket_id)) is not None


# --- ServiceNow Connector ---


def _snow_post_ok():
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(
        return_value=MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(
                return_value={
                    "result": {"sys_id": "abc123", "number": "CHG0012345", "state": "new"}
                }
            ),
        )
    )
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    return mock_cm, mock_client


@pytest.mark.asyncio
async def test_servicenow_create_change_request():
    connector = ServiceNowConnector("https://corp.service-now.com", "user", "pass")
    mock_cm, mock_client = _snow_post_ok()
    with patch(
        "services.integrations.servicenow_connector.httpx.AsyncClient", return_value=mock_cm
    ):
        result = await connector.create_change_request(
            short_description="Patch openssl", description="desc"
        )
    assert result["number"] == "CHG0012345"
    assert result["sys_id"] == "abc123"
    assert "Authorization" in mock_client.post.call_args.kwargs["headers"]


@pytest.mark.asyncio
async def test_servicenow_update_change_request():
    connector = ServiceNowConnector("https://corp.service-now.com", "user", "pass")
    mock_client = AsyncMock()
    mock_client.patch = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)
    with patch(
        "services.integrations.servicenow_connector.httpx.AsyncClient", return_value=mock_cm
    ):
        ok = await connector.update_change_request("abc123", "closed")
    assert ok is True
    assert mock_client.patch.call_args.kwargs["json"] == {"state": "closed"}


@pytest.mark.asyncio
async def test_sync_servicenow_persists(db):
    connector = ServiceNowConnector("https://corp.service-now.com", "user", "pass")
    mock_cm, _ = _snow_post_ok()
    with patch(
        "services.integrations.servicenow_connector.httpx.AsyncClient", return_value=mock_cm
    ):
        ticket = await sync_servicenow_change_request(
            db,
            connector,
            vulnerability_id=uuid.uuid4(),
            cve_id="CVE-2026-0001",
            asset_hostname="srv-1",
            plan_id=str(uuid.uuid4()),
        )
    assert ticket.system_name == "SERVICENOW"
    assert ticket.external_ticket_id == "CHG0012345"


# --- Rollback Endpoint ---


@pytest.mark.asyncio
async def test_rollback_patch_job(db):
    asset, plan = await _seed_asset_and_plan(db, status="APPROVED")
    plan.plan_payload = {
        "actions": [
            {"rollback_command_template": "apt-get install openssl=3.0.1"},
            {"rollback_command_template": "systemctl restart apache2"},
        ]
    }
    await db.commit()

    job = PatchJob(
        plan_id=plan.plan_id,
        execution_type="AGENTLESS_SSH",
        status="SUCCESS",
        execution_logs=["ok"],
        rollback_available=True,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    resp: PatchJobResponse = await rollback_patch_job(job.job_id, db)
    assert resp.status == "ROLLED_BACK"
    assert "Emergency rollback triggered" in resp.execution_logs
    assert len(resp.snapshot_metadata["rollback"]["commands"]) == 2

    audit = (await db.execute(select(AuditEvent))).scalars().first()
    assert audit.action == "PATCH_ROLLED_BACK"
