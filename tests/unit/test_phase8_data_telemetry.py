import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from services.control_plane.core import security
from services.llm_planner.providers import LLMProvider, MultiProviderPlanner, estimate_llm_cost
from services.llm_planner.telemetry import (
    compute_prompt_hash,
    get_ai_telemetry_stats,
    list_ai_activity_logs,
    record_ai_activity,
)
from services.models.db_models import AIActivityLog, Base, ITSMTicket, RiskException
from services.risk_engine.sla_tracker import (
    CRITICAL_SLA_DAYS,
    HIGH_SLA_DAYS,
    KEV_SLA_DAYS,
    STANDARD_SLA_DAYS,
    check_escalation,
    compute_sla_deadline,
    compute_sla_status,
    sla_days_for,
    sla_tier_for,
)


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as session:
        yield session
    await engine.dispose()


# --- SLA Tracker ---


def test_sla_days_for_tiers():
    assert sla_days_for(9.0, True) == KEV_SLA_DAYS
    assert sla_days_for(8.5, False) == CRITICAL_SLA_DAYS
    assert sla_days_for(6.5, False) == HIGH_SLA_DAYS
    assert sla_days_for(2.0, False) == STANDARD_SLA_DAYS


def test_sla_tier_for():
    assert sla_tier_for(9.0, True) == "KEV"
    assert sla_tier_for(8.5, False) == "CRITICAL"
    assert sla_tier_for(6.5, False) == "HIGH"
    assert sla_tier_for(2.0, False) == "STANDARD"


def test_compute_sla_deadline_is_future():
    deadline = compute_sla_deadline(9.0, True)
    assert deadline.tzinfo is None
    assert deadline > datetime.now(UTC).replace(tzinfo=None) - timedelta(seconds=5)


def test_compute_sla_status_breached():
    past = datetime.now(UTC).replace(tzinfo=None) - timedelta(days=1)
    status = compute_sla_status(past)
    assert status["status"] == "BREACHED"
    assert status["escalation_required"] is False
    assert status["hours_remaining"] < 0


def test_compute_sla_status_escalation_window():
    deadline = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=24)
    status = compute_sla_status(deadline)
    assert status["status"] == "ESCALATED"
    assert status["escalation_required"] is True


def test_compute_sla_status_on_track():
    deadline = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=20)
    status = compute_sla_status(deadline)
    assert status["status"] == "ON_TRACK"
    assert status["escalation_required"] is False


def test_check_escalation():
    deadline = datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=30)
    assert check_escalation(deadline) is True
    far_deadline = datetime.now(UTC).replace(tzinfo=None) + timedelta(days=10)
    assert check_escalation(far_deadline) is False


# --- Security Core ---


def test_password_hash_verify_roundtrip():
    hashed = security.hash_password("s3cret!")
    assert hashed != "s3cret!"
    assert security.verify_password("s3cret!", hashed) is True
    assert security.verify_password("wrong", hashed) is False


def test_password_sha256_fallback_verification():
    import hashlib
    import secrets

    salt = secrets.token_hex(16)
    hashed = f"sha256${salt}${hashlib.sha256((salt + 'pw').encode()).hexdigest()}"
    assert security.verify_password("pw", hashed) is True
    assert security.verify_password("nope", hashed) is False


def test_jwt_roundtrip():
    token = security.create_access_token("user@example.com", extra_claims={"role": "admin"})
    payload = security.decode_access_token(token)
    assert payload["sub"] == "user@example.com"
    assert payload["role"] == "admin"


def test_jwt_invalid_token():
    assert security.decode_access_token("not.a.jwt") is None


def test_hmac_signature_verify():
    payload = b"hello world"
    sig = security.compute_hmac_signature(payload)
    assert security.verify_hmac_signature(payload, sig) is True
    assert security.verify_hmac_signature(b"tampered", sig) is False


def test_hmac_signature_json():
    payload = {"plan_id": str(uuid.uuid4()), "decision": "APPROVED"}
    sig = security.compute_hmac_signature_json(payload)
    assert security.verify_hmac_signature_json(payload, sig) is True
    tampered = dict(payload, decision="REJECTED")
    assert security.verify_hmac_signature_json(tampered, sig) is False


# --- LLM Providers ---


def test_estimate_llm_cost():
    cost = estimate_llm_cost(1000, 500)
    expected = (1000 * 0.000005) + (500 * 0.000015)
    assert cost == round(expected, 6)
    assert cost > 0


_VALID_PLAN = {
    "actions": [
        {
            "action_type": "patch",
            "target_package": "openssl",
            "method": "apt",
            "target_version": "3.0.2",
            "restart_required": False,
            "rollback_command_template": "apt-get install openssl=3.0.1",
            "pre_patch_checks": ["check_disk_space"],
        }
    ],
    "estimated_risk_after_patch": "low",
    "explanation": "Upgrade openssl to patched version.",
}


class _FailingProvider(LLMProvider):
    name = "failing"
    model = "fail"

    async def generate(self, system_prompt, user_prompt):
        raise RuntimeError("provider down")


class _GoodProvider(LLMProvider):
    name = "good"
    model = "good"

    async def generate(self, system_prompt, user_prompt):
        return json.dumps(_VALID_PLAN)


class _InvalidJsonProvider(LLMProvider):
    name = "badjson"
    model = "badjson"

    async def generate(self, system_prompt, user_prompt):
        return "not json"


@pytest.mark.asyncio
async def test_multiprovider_failover():
    planner = MultiProviderPlanner(providers=[_FailingProvider(), _GoodProvider()], max_retries=2)
    plan = await planner.generate_remediation_plan("sys", "user")
    assert plan["actions"][0]["target_package"] == "openssl"


@pytest.mark.asyncio
async def test_multiprovider_schema_retry_then_fallback():
    def fallback():
        return _VALID_PLAN

    planner = MultiProviderPlanner(
        providers=[_InvalidJsonProvider()], max_retries=2, fallback_plan_builder=fallback
    )
    plan = await planner.generate_remediation_plan("sys", "user")
    assert plan == _VALID_PLAN


@pytest.mark.asyncio
async def test_multiprovider_all_fail_raises():
    planner = MultiProviderPlanner(providers=[_FailingProvider()], max_retries=1)
    with pytest.raises(RuntimeError):
        await planner.generate_remediation_plan("sys", "user")


# --- AI Telemetry ---


def test_compute_prompt_hash_deterministic():
    assert compute_prompt_hash("abc") == compute_prompt_hash("abc")
    assert compute_prompt_hash("abc") != compute_prompt_hash("abd")


@pytest.mark.asyncio
async def test_record_ai_activity_persists(db):
    log = await record_ai_activity(
        db,
        provider="openai",
        model="gpt-4o-mini",
        prompt_tokens=120,
        completion_tokens=45,
        latency_ms=320.5,
        sanitizer_passed=True,
        prompt_text="Asset: web-1",
        vulnerability_id=str(uuid.uuid4()),
    )
    assert log.provider == "openai"
    assert log.total_tokens == 165
    assert log.estimated_cost_usd > 0
    assert log.prompt_hash == compute_prompt_hash("Asset: web-1")

    count = (await db.execute(select(func.count(AIActivityLog.log_id)))).scalar_one()
    assert count == 1


@pytest.mark.asyncio
async def test_ai_telemetry_stats_aggregation(db):
    await record_ai_activity(
        db, provider="openai", model="gpt-4o-mini", prompt_tokens=100, completion_tokens=50
    )
    await record_ai_activity(
        db, provider="openai", model="gpt-4o-mini", prompt_tokens=200, completion_tokens=100
    )
    await record_ai_activity(
        db, provider="ollama", model="llama3", prompt_tokens=10, completion_tokens=5
    )

    stats = await get_ai_telemetry_stats(db)
    assert stats["total_prompts"] == 3
    assert stats["total_prompt_tokens"] == 310
    assert stats["total_completion_tokens"] == 155
    assert stats["total_tokens"] == 465
    assert stats["total_estimated_cost_usd"] > 0

    by_provider = {p["provider"]: p for p in stats["by_provider"]}
    assert by_provider["openai"]["prompts"] == 2
    assert by_provider["ollama"]["prompts"] == 1


@pytest.mark.asyncio
async def test_list_ai_activity_logs(db):
    await record_ai_activity(
        db, provider="openai", model="gpt-4o-mini", prompt_tokens=10, completion_tokens=5
    )
    await record_ai_activity(
        db, provider="ollama", model="llama3", prompt_tokens=10, completion_tokens=5
    )

    logs = await list_ai_activity_logs(db, limit=1)
    assert len(logs) == 1
    assert logs[0].provider in ("openai", "ollama")


# --- New DB Models ---


@pytest.mark.asyncio
async def test_new_db_models_roundtrip(db):
    # Build a minimal asset+vulnerability to satisfy FKs
    from services.models.db_models import Asset, Vulnerability

    asset = Asset(
        hostname="srv-1",
        os_type="debian",
        environment="production",
        criticality_score=8,
        exposure_level="internet-facing",
    )
    db.add(asset)
    await db.flush()

    vuln = Vulnerability(
        asset_id=asset.asset_id,
        cve_id="CVE-2026-0001",
        package_name="openssl",
        installed_version="1.0",
        fixed_version="1.1",
        cvss_score=9.8,
        epss_score=0.9,
        is_known_exploited=True,
        calculated_risk_score=9.5,
        status="OPEN",
    )
    db.add(vuln)
    await db.flush()

    ai_log = AIActivityLog(
        vulnerability_id=str(vuln.vulnerability_id),
        provider="openai",
        model="gpt-4o-mini",
        prompt_tokens=10,
        completion_tokens=5,
        estimated_cost_usd=0.0001,
    )
    db.add(ai_log)

    exception = RiskException(
        vulnerability_id=vuln.vulnerability_id,
        requester="analyst@corp.com",
        justification="Third-party dependency, fix not yet available.",
        compensating_controls="Network isolation + WAF rule.",
        expires_at=datetime.now(UTC).replace(tzinfo=None) + timedelta(days=30),
        status="ACTIVE",
    )
    db.add(exception)

    ticket = ITSMTicket(
        vulnerability_id=vuln.vulnerability_id,
        system_name="JIRA",
        external_ticket_id="SEC-123",
        ticket_url="https://jira.example.com/browse/SEC-123",
        status="OPEN",
    )
    db.add(ticket)
    await db.commit()

    assert (await db.get(AIActivityLog, ai_log.log_id)) is not None
    assert (await db.get(RiskException, exception.exception_id)) is not None
    assert (await db.get(ITSMTicket, ticket.ticket_id)) is not None


# --- AI Telemetry API ---


@pytest.mark.asyncio
async def test_ai_telemetry_api_stats(db):
    from services.control_plane.api.v1.ai_telemetry import ai_stats

    await record_ai_activity(
        db, provider="openai", model="gpt-4o-mini", prompt_tokens=100, completion_tokens=50
    )
    stats = await ai_stats(db)
    assert stats["total_prompts"] == 1
    assert stats["by_provider"][0]["provider"] == "openai"


@pytest.mark.asyncio
async def test_ai_telemetry_api_logs(db):
    from services.control_plane.api.v1.ai_telemetry import ai_logs

    await record_ai_activity(
        db,
        provider="openai",
        model="gpt-4o-mini",
        prompt_tokens=10,
        completion_tokens=5,
        prompt_text="Asset: web-1",
    )
    logs = await ai_logs(limit=10, offset=0, db=db)
    assert len(logs) == 1
    assert logs[0]["provider"] == "openai"
    assert logs[0]["prompt_hash"] is not None
    assert logs[0]["total_tokens"] == 15


# --- Phase 8 Metrics ---


def test_phase8_metrics_record_without_error():
    from services.observability import metrics

    metrics.record_scan_ingested("trivy")
    metrics.record_remediation_plan("PENDING_APPROVAL")
    metrics.record_patch_execution_duration("AGENTLESS_SSH", 1.25)
    metrics.record_opa_evaluation("allowed")
    metrics.set_audit_chain_valid(True)
    metrics.set_audit_chain_valid(False)
    metrics.record_ai_tokens("openai", "gpt-4o-mini", "prompt", 100)
    metrics.record_ai_tokens("openai", "gpt-4o-mini", "completion", 50)
    metrics.record_ai_cost(0.00125)

    body = metrics.get_metrics().body
    if isinstance(body, bytes):
        body = body.decode("utf-8")
    assert "nexora_scans_ingested_total" in body
    assert "nexora_remediation_plans_total" in body
    assert "nexora_patch_execution_duration_seconds" in body
    assert "nexora_opa_evaluations_total" in body
    assert "nexora_audit_chain_valid" in body
    assert "nexora_ai_tokens_total" in body
    assert "nexora_ai_cost_dollars_total" in body


def test_vulnerability_has_sla_deadline_column(db):
    from services.models.db_models import Vulnerability

    assert hasattr(Vulnerability, "sla_deadline")
