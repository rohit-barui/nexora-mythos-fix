from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.v2_agent.agent import V2Agent, get_agent


@pytest.mark.asyncio
async def test_v2_agent_start_stop():
    agent = V2Agent("http://localhost:8000", agent_id="test-agent", api_key="test-key")

    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json = MagicMock(return_value={"status": "registered"})

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.aclose = AsyncMock()

    with patch("services.v2_agent.agent.httpx.AsyncClient", return_value=mock_client):
        await agent.start()
        assert agent._running is True
        await agent.stop()
        assert agent._running is False


@pytest.mark.asyncio
async def test_v2_agent_collect_telemetry():
    agent = V2Agent("http://localhost:8000", agent_id="test-agent")
    telemetry = await agent.collect_telemetry()
    assert telemetry["agent_id"] == "test-agent"
    assert "timestamp" in telemetry
    assert telemetry["status"] == "healthy"
    assert "metrics" in telemetry


@pytest.mark.asyncio
async def test_security_headers_middleware():
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from services.control_plane.middleware import SecurityHeadersMiddleware

    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    client = TestClient(app)
    resp = client.get("/test")
    assert resp.status_code == 200
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert resp.headers["X-XSS-Protection"] == "1; mode=block"


@pytest.mark.asyncio
async def test_rate_limit_middleware():
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from services.control_plane.middleware import RateLimitMiddleware

    app = FastAPI()
    app.add_middleware(RateLimitMiddleware, requests_per_minute=2)

    @app.get("/test")
    async def test_endpoint():
        return {"ok": True}

    client = TestClient(app)
    resp1 = client.get("/test")
    assert resp1.status_code == 200
    resp2 = client.get("/test")
    assert resp2.status_code == 200
    resp3 = client.get("/test")
    assert resp3.status_code == 429
    assert "Rate limit exceeded" in resp3.json()["detail"]


@pytest.mark.asyncio
async def test_api_key_middleware():
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from services.control_plane.middleware import APIKeyMiddleware

    app = FastAPI()
    app.add_middleware(APIKeyMiddleware, api_key="test-secret")

    @app.get("/protected")
    async def protected():
        return {"ok": True}

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    client = TestClient(app)
    # Exempt path
    resp = client.get("/health")
    assert resp.status_code == 200

    # Missing auth
    resp = client.get("/protected")
    assert resp.status_code == 401

    # Wrong key
    resp = client.get("/protected", headers={"Authorization": "Bearer wrong"})
    assert resp.status_code == 401

    # Correct key
    resp = client.get("/protected", headers={"Authorization": "Bearer test-secret"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_prometheus_metrics():
    from fastapi import FastAPI
    from starlette.testclient import TestClient

    from services.observability.metrics import get_metrics

    app = FastAPI()
    app.get("/metrics")(get_metrics)

    client = TestClient(app)
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "nexora_http_requests_total" in resp.text
    assert "nexora_http_request_duration_seconds" in resp.text


@pytest.mark.asyncio
async def test_record_metrics():
    from services.observability.metrics import record_patch_job, record_vulnerability_ingested

    record_patch_job("SUCCESS")
    record_vulnerability_ingested("trivy")

    # Metrics are internal counters, just verify no exception
    assert True


@pytest.mark.asyncio
async def test_get_agent_singleton():
    agent1 = await get_agent("http://localhost:8000", "agent-1")
    agent2 = await get_agent("http://localhost:8000", "agent-1")
    assert agent1 is agent2
