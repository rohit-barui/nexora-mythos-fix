from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.audit.ledger import AuditLedger
from services.control_plane.main import app
from services.integrations.notifier import (
    NotificationService,
    SlackNotifier,
    TeamsNotifier,
    WebhookNotifier,
    get_notification_service,
)
from services.models.db_models import Asset, Base, PatchJob, RemediationPlan, Vulnerability


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


@pytest.fixture
async def seeded_db(db):
    # Create test data
    asset = Asset(hostname="web-01", os_type="debian", criticality_score=8)
    db.add(asset)
    await db.flush()

    vuln1 = Vulnerability(
        asset_id=asset.asset_id,
        cve_id="CVE-1",
        package_name="openssl",
        installed_version="1.0",
        cvss_score=9.8,
        calculated_risk_score=9.5,
        status="OPEN",
    )
    vuln2 = Vulnerability(
        asset_id=asset.asset_id,
        cve_id="CVE-2",
        package_name="curl",
        installed_version="7.0",
        cvss_score=5.0,
        calculated_risk_score=4.8,
        status="OPEN",
    )
    db.add_all([vuln1, vuln2])

    plan = RemediationPlan(
        asset_id=asset.asset_id,
        vulnerability_ids=[str(vuln1.vulnerability_id)],
        plan_payload={"actions": []},
        opa_evaluation_result={},
        status="APPROVED",
    )
    db.add(plan)
    await db.flush()

    job = PatchJob(
        plan_id=plan.plan_id,
        execution_type="AGENTLESS_SSH",
        status="SUCCESS",
        execution_logs=["done"],
        snapshot_metadata={},
    )
    db.add(job)
    await db.flush()

    await AuditLedger.log_event(db, "system", "TEST_EVENT", {"test": True})
    await db.commit()
    return db


@pytest.mark.asyncio
async def test_dashboard_stats(seeded_db):
    from httpx import ASGITransport, AsyncClient

    from services.control_plane.core.db import get_db

    async def override_get_db():
        yield seeded_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/dashboard/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["assets"]["total"] == 1
        assert data["vulnerabilities"]["total"] == 2
        assert data["vulnerabilities"]["critical"] == 1
        assert data["remediation_plans"]["total"] == 1
        assert data["patch_jobs"]["total"] == 1
        assert data["patch_jobs"]["successful"] == 1
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_dashboard_vuln_trends(seeded_db):
    from httpx import ASGITransport, AsyncClient

    from services.control_plane.core.db import get_db

    async def override_get_db():
        yield seeded_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/dashboard/vulnerability-trends?days=30")
        assert resp.status_code == 200
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_dashboard_risk_distribution(seeded_db):
    from httpx import ASGITransport, AsyncClient

    from services.control_plane.core.db import get_db

    async def override_get_db():
        yield seeded_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/dashboard/risk-distribution")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, dict)
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_dashboard_top_assets(seeded_db):
    from httpx import ASGITransport, AsyncClient

    from services.control_plane.core.db import get_db

    async def override_get_db():
        yield seeded_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/dashboard/top-assets-by-risk?limit=10")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["hostname"] == "web-01"
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_dashboard_audit_verify(seeded_db):
    from httpx import ASGITransport, AsyncClient

    from services.control_plane.core.db import get_db

    async def override_get_db():
        yield seeded_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/api/v1/dashboard/audit/verify")
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
    app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_webhook_notifier():
    notifier = WebhookNotifier("http://localhost/webhook")
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("services.integrations.notifier.httpx.AsyncClient", return_value=mock_cm):
        result = await notifier.send("Test", "Message", {"key": "val"}, "info")
        assert result is True
        mock_client.post.assert_called_once()


@pytest.mark.asyncio
async def test_slack_notifier():
    notifier = SlackNotifier("https://hooks.slack.com/test")
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("services.integrations.notifier.httpx.AsyncClient", return_value=mock_cm):
        result = await notifier.send("Alert", "Something happened", {"cve": "CVE-1"}, "critical")
        assert result is True
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert "attachments" in call_args.kwargs["json"]


@pytest.mark.asyncio
async def test_teams_notifier():
    notifier = TeamsNotifier("https://outlook.office.com/webhook")
    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    with patch("services.integrations.notifier.httpx.AsyncClient", return_value=mock_cm):
        result = await notifier.send("Title", "Body", {"data": "x"}, "warning")
        assert result is True
        mock_client.post.assert_called_once()
        call_args = mock_client.post.call_args
        assert (
            call_args.kwargs["json"]["attachments"][0]["contentType"]
            == "application/vnd.microsoft.card.adaptive"
        )


@pytest.mark.asyncio
async def test_notification_service_register_and_notify():
    service = NotificationService()
    mock_channel = MagicMock(spec=["send"])
    mock_channel.send = AsyncMock(return_value=True)
    service.register("test-channel", mock_channel)

    results = await service.notify(
        "Title", "Message", {"data": "test"}, "info", channels=["test-channel"]
    )
    assert results == {"test-channel": True}
    mock_channel.send.assert_awaited_once_with("Title", "Message", {"data": "test"}, "info")


@pytest.mark.asyncio
async def test_notification_service_missing_channel():
    service = NotificationService()
    results = await service.notify("Title", "Message", channels=["nonexistent"])
    assert results == {"nonexistent": False}


@pytest.mark.asyncio
async def test_get_notification_service_singleton():
    s1 = get_notification_service()
    s2 = get_notification_service()
    assert s1 is s2


@pytest.mark.asyncio
async def test_notifications_api_register_webhook():
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/api/v1/notifications/webhooks",
            json={
                "name": "test-webhook",
                "webhook_url": "http://localhost:9999/hook",
                "template": '{"text": "{title}: {message}"}',
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "test-webhook"
        assert data["type"] == "webhook"

        # list
        resp = await client.get("/api/v1/notifications/configs")
        assert resp.status_code == 200
        assert len(resp.json()) == 1

        # delete
        resp = await client.delete("/api/v1/notifications/configs/test-webhook")
        assert resp.status_code == 200


@pytest.mark.asyncio
async def test_notifications_api_send_test():
    from unittest.mock import AsyncMock, MagicMock, patch

    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Register a webhook first
        await client.post(
            "/api/v1/notifications/webhooks",
            json={"name": "test-hook", "webhook_url": "http://localhost:9999/hook"},
        )
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=MagicMock(raise_for_status=MagicMock()))
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
        mock_cm.__aexit__ = AsyncMock(return_value=None)

        with patch("services.integrations.notifier.httpx.AsyncClient", return_value=mock_cm):
            resp = await client.post(
                "/api/v1/notifications/test",
                json={
                    "title": "Test",
                    "message": "Test message",
                    "level": "info",
                    "channels": ["test-hook"],
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["results"]["test-hook"] is True
