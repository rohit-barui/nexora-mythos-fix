"""Phase 11 tests: V2 Agent gRPC/mTLS upgrade + A/B rollback."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.execution_engine.ab_rollback import DualSlotManager
from services.v2_agent import agent_pb2
from services.v2_agent.grpc_client import AgentGRPCClient
from services.v2_agent.grpc_server import AgentServiceServicer, GRPCAgentServer
from services.v2_agent.mtls import (
    ensure_cert_kit,
    generate_self_signed_ca,
    generate_self_signed_cert,
)

# ---- mTLS certificate utilities ----


def test_self_signed_ca_generated():
    cert, key = generate_self_signed_ca("nexora-test-ca")
    assert "BEGIN CERTIFICATE" in cert
    assert "BEGIN PRIVATE KEY" in key


def test_self_signed_identity_cert_generated():
    cert, key = generate_self_signed_cert("nexora-test-agent")
    assert "BEGIN CERTIFICATE" in cert
    assert "BEGIN PRIVATE KEY" in key


def test_ensure_cert_kit_materializes_paths():
    import tempfile

    directory = tempfile.mkdtemp(prefix="nexora-tls-test")
    with patch("services.v2_agent.mtls.cert_dir", return_value=directory):
        paths = ensure_cert_kit("test-identity")
    assert paths["ca_cert"].endswith("ca.pem")
    assert paths["cert"].endswith("test-identity.crt")
    assert paths["key"].endswith("test-identity.key")


# ---- gRPC servicer unit tests ----


def test_servicer_register_accepts_agent():
    servicer = AgentServiceServicer()
    resp = servicer.Register(agent_pb2.RegisterRequest(agent_id="agent-1", version="2.0.0"), None)
    assert resp.accepted is True
    assert resp.server_version == "2.0.0-grpc"
    assert "agent-1" in AgentServiceServicer.REGISTERED_AGENTS


def test_servicer_heartbeat_acknowledges():
    servicer = AgentServiceServicer()
    resp = servicer.Heartbeat(
        agent_pb2.HeartbeatRequest(agent_id="agent-1", status="healthy", cpu_percent=5.5), None
    )
    assert resp.received is True
    assert "agent-1" in resp.message


@pytest.mark.asyncio
async def test_servicer_execute_requires_registered_agent():
    from grpc import StatusCode
    from grpc._channel import _InactiveRpcError

    servicer = AgentServiceServicer()

    class FakeContext:
        def __init__(self):
            self.code = None
            self.details = None

        def abort(self, code, details):
            self.code = code
            self.details = details
            raise _InactiveRpcError(("", None, None, None))

    ctx = FakeContext()
    with pytest.raises(Exception):
        await servicer.Execute(agent_pb2.ExecuteRequest(agent_id="ghost", action="patch"), ctx)
    assert ctx.code == StatusCode.PERMISSION_DENIED


@pytest.mark.asyncio
async def test_servicer_execute_dispatches_executor():
    async def fake_executor(action, package, payload):
        return {"status": "SUCCESS", "message": f"patched {package}"}

    servicer = AgentServiceServicer(executor=fake_executor)
    servicer.Register(agent_pb2.RegisterRequest(agent_id="agent-1", version="2.0.0"), None)
    resp = await servicer.Execute(
        agent_pb2.ExecuteRequest(agent_id="agent-1", action="patch", package="openssl"), None
    )
    assert resp.status == "SUCCESS"
    assert "openssl" in resp.message
    assert resp.execution_id


# ---- gRPC client unit tests (mocked channel) ----


@pytest.mark.asyncio
async def test_grpc_client_register_maps_response():
    client = AgentGRPCClient(agent_id="ctl-1")
    stub = MagicMock()
    stub.Register = AsyncMock(
        return_value=agent_pb2.RegisterResponse(
            accepted=True, agent_id="agent-7", server_version="2.0.0-grpc"
        )
    )
    client._channel = MagicMock()
    client._stub = stub
    result = await client.register("agent-7", "2.0.0", ["patch_execution"])
    assert result["accepted"] is True
    assert result["agent_id"] == "agent-7"


@pytest.mark.asyncio
async def test_grpc_client_execute_maps_response():
    client = AgentGRPCClient(agent_id="ctl-1")
    stub = MagicMock()
    stub.Execute = AsyncMock(
        return_value=agent_pb2.ExecuteResponse(
            status="SUCCESS", action="patch", message="done", execution_id="exec-1"
        )
    )
    client._channel = MagicMock()
    client._stub = stub
    result = await client.execute("agent-7", "patch", "curl")
    assert result["status"] == "SUCCESS"
    assert result["execution_id"] == "exec-1"


@pytest.mark.asyncio
async def test_grpc_client_close_resets_channel():
    client = AgentGRPCClient(agent_id="ctl-1")
    client._channel = MagicMock()
    client._channel.close = AsyncMock()
    client._stub = MagicMock()
    await client.close()
    assert client._channel is None
    assert client._stub is None


# ---- A/B dual-slot rollback ----


def test_dual_slot_promote_switches_inactive_slot():
    manager = DualSlotManager("app", active_slot="A")
    result = manager.promote("2.0.0")
    assert result["slot"] == "B"
    assert result["state"] == "PENDING_VERIFY"


def test_dual_slot_confirm_flips_active_traffic():
    manager = DualSlotManager("app", active_slot="A")
    manager.promote("2.0.0")
    result = manager.confirm()
    assert result["active_slot"] == "B"
    assert manager.active["tag"] == "2.0.0"


def test_dual_slot_rollback_restores_previous_slot():
    manager = DualSlotManager("app", active_slot="A")
    manager.promote("2.0.0")
    result = manager.rollback()
    assert result["status"] == "ROLLED_BACK"
    assert manager.active_slot == "A"
    assert manager.active["tag"] == "1.0.0"


def test_dual_slot_current_state_reports_slots():
    manager = DualSlotManager("app")
    state = manager.current_state()
    assert state["image"] == "app"
    assert set(state["slots"].keys()) == {"A", "B"}


# ---- End-to-end gRPC server + client ----


@pytest.mark.asyncio
async def test_grpc_roundtrip_live():
    import os
    import tempfile

    tls_dir = tempfile.mkdtemp(prefix="nexora-grpc-live")
    with patch.dict(os.environ, {"NEXORA_TLS_DIR": tls_dir}):
        server = GRPCAgentServer(bind_address="localhost:50056")
        await server.start()
        try:
            client = AgentGRPCClient(target="localhost:50056", agent_id="ctl-1")
            reg = await client.register("agent-e2e", "2.0.0", ["patch_execution"])
            assert reg["accepted"] is True
            hb = await client.heartbeat("agent-e2e", "healthy", {"cpu_percent": 1.0})
            assert hb["received"] is True
            status = await client.get_status("agent-e2e")
            assert status["status"] == "healthy"
            await client.close()
        finally:
            await server.stop()
