import httpx
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.control_plane.core.db import get_db
from services.control_plane.main import app
from services.models.db_models import Base

TRIVY_PAYLOAD = {
    "Results": [
        {
            "Target": "debian:12",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2022-3786",
                    "PkgName": "openssl",
                    "InstalledVersion": "3.0.2",
                    "FixedVersion": "3.0.3",
                    "CVSS": {"nvd": {"V3Score": 9.8}},
                }
            ],
        }
    ]
}


@pytest.fixture
async def client():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers={"X-Test-Bypass": "true"}
    ) as c:
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()


async def _create_asset(client) -> str:
    resp = await client.post(
        "/api/v1/assets",
        json={
            "hostname": "web-prod-01",
            "os_type": "debian",
            "environment": "development",
            "criticality_score": 5,
            "exposure_level": "internal",
        },
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["asset_id"]


@pytest.mark.asyncio
async def test_full_remediation_journey(client):
    # 1. Asset
    asset_id = await _create_asset(client)

    # 2. Ingest vulnerability
    resp = await client.post(
        f"/api/v1/vulnerabilities/ingest/{asset_id}",
        params={"scanner_type": "trivy"},
        json=TRIVY_PAYLOAD,
    )
    assert resp.status_code == 200, resp.text
    vuln_id = resp.json()[0]["vulnerability_id"]
    assert resp.json()[0]["calculated_risk_score"] > 0

    # 3. Generate remediation plan
    resp = await client.post(
        "/api/v1/remediation/generate",
        json={"asset_id": asset_id, "vulnerability_ids": [vuln_id]},
    )
    assert resp.status_code == 200, resp.text
    plan = resp.json()
    assert plan["status"] in ("PENDING_APPROVAL", "REJECTED_BY_POLICY")
    assert plan["plan_payload"]["actions"][0]["target_package"] == "openssl"
    plan_id = plan["plan_id"]

    # 4. Approval
    resp = await client.post(
        "/api/v1/approvals",
        json={
            "plan_id": plan_id,
            "approver": "admin@nexora.io",
            "decision": "APPROVED",
            "channel": "WEB_DASHBOARD",
        },
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["decision"] == "APPROVED"

    # 5. Create + execute patch job
    resp = await client.post(
        "/api/v1/patch-jobs", json={"plan_id": plan_id, "execution_type": "AGENTLESS_SSH"}
    )
    assert resp.status_code == 201, resp.text
    job_id = resp.json()["job_id"]

    resp = await client.post(f"/api/v1/patch-jobs/{job_id}/execute")
    assert resp.status_code == 200, resp.text
    execution = resp.json()
    assert execution["overall_status"] == "SUCCESS"
    assert execution["action_count"] == 1
    assert execution["actions"][0]["status"] == "SUCCESS"

    # 6. Audit ledger integrity
    resp = await client.get("/api/v1/audit/verify")
    assert resp.status_code == 200, resp.text
    audit = resp.json()
    assert audit["valid"] is True
    assert audit["event_count"] == 2  # approval decision + patch executed

    resp = await client.get("/api/v1/audit")
    assert resp.status_code == 200
    actions = {e["action"] for e in resp.json()}
    assert {"APPROVAL_DECISION", "PATCH_EXECUTED"} <= actions


@pytest.mark.asyncio
async def test_execution_blocked_without_approval(client):
    asset_id = await _create_asset(client)
    resp = await client.post(
        f"/api/v1/vulnerabilities/ingest/{asset_id}",
        params={"scanner_type": "trivy"},
        json=TRIVY_PAYLOAD,
    )
    vuln_id = resp.json()[0]["vulnerability_id"]
    resp = await client.post(
        "/api/v1/remediation/generate",
        json={"asset_id": asset_id, "vulnerability_ids": [vuln_id]},
    )
    plan_id = resp.json()["plan_id"]

    resp = await client.post("/api/v1/patch-jobs", json={"plan_id": plan_id})
    job_id = resp.json()["job_id"]

    resp = await client.post(f"/api/v1/patch-jobs/{job_id}/execute")
    assert resp.status_code == 409  # plan not APPROVED yet
    assert "must be APPROVED" in resp.json()["detail"]
