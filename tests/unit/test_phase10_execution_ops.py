"""Phase 10 tests: Execution & Ops (SSM, containers, canary, secrets, rescan, CLI)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from services.cli import main
from services.execution_engine.aws_ssm_adapter import AWSSSMAdapter
from services.execution_engine.container_patcher import ContainerPatcher
from services.execution_engine.registry import ExecutionAdapterRegistry
from services.execution_engine.secrets_manager import InProcessSecrets, SecretsManager
from services.ingestion.rescan_verifier import RescanVerifier
from services.orchestrator.canary import CanaryDeployment, Redlock
from services.orchestrator.engine import OrchestrationEngine

# ---- AWS SSM Adapter (Pillar 6) ----


@pytest.mark.asyncio
async def test_ssm_dry_run_builds_ssm_command():
    adapter = AWSSSMAdapter(region="eu-west-1")
    commands = await adapter.dry_run(
        "i-012345",
        {"target_package": "openssl"},
    )
    assert commands[0].startswith("ssm send-command")
    assert "i-012345" in commands[0]


@pytest.mark.asyncio
async def test_ssm_execute_falls_back_when_boto3_unavailable():
    adapter = AWSSSMAdapter()
    with patch.object(adapter, "_get_client", side_effect=ImportError("no boto3")):
        result = await adapter.execute_patch(
            "i-012345", {"target_package": "openssl", "target_version": "3.0"}, {}
        )
    assert result["status"] == "SUCCESS"
    assert "local-fallback" in result["ssm_command_id"]
    assert "openssl" in result["executed_command"]


@pytest.mark.asyncio
async def test_ssm_execute_sends_real_command_when_client_available():
    adapter = AWSSSMAdapter()
    client = MagicMock()
    client.send_command.return_value = {"Command": {"CommandId": "cmd-123"}}
    with patch.object(adapter, "_get_client", return_value=client):
        result = await adapter.execute_patch("i-abc", {"target_package": "curl"}, {})
    assert result["ssm_command_id"] == "cmd-123"
    assert result["status"] == "SUCCESS"


@pytest.mark.asyncio
async def test_ssm_rollback_returns_queued_command():
    adapter = AWSSSMAdapter()
    result = await adapter.execute_rollback(
        "i-012345", {"rollback_command_template": "sudo apt-get install -y openssl=1.1"}, {}
    )
    assert result["status"] == "ROLLED_BACK"
    assert "openssl=1.1" in result["executed_command"]


# ---- Container Patcher (Pillar 7) ----


@pytest.mark.asyncio
async def test_container_patcher_rewrites_dockerfile_tag():
    patcher = ContainerPatcher()
    manifest = "FROM nginx:1.0\nRUN apt update\n"
    rewritten = patcher.rewrite_manifest(
        manifest, {"target_package": "nginx", "target_version": "1.25"}
    )
    assert "FROM nginx:1.25" in rewritten
    assert "RUN apt update" in rewritten


@pytest.mark.asyncio
async def test_container_patcher_rewrites_docker_compose_image():
    patcher = ContainerPatcher()
    manifest = "services:\n  web:\n    image: nginx:1.0\n"
    rewritten = patcher.rewrite_manifest(
        manifest, {"target_package": "nginx", "target_version": "1.26"}
    )
    assert "image: nginx:1.26" in rewritten


@pytest.mark.asyncio
async def test_container_patcher_rejects_corrupt_digest():
    patcher = ContainerPatcher()
    result = await patcher.execute_patch(
        "repo/app",
        {
            "target_package": "nginx",
            "target_version": "1.25",
            "dockerfile_content": "FROM nginx:1.0\nCORRUPT",
        },
        {},
    )
    assert result["status"] == "FAILED"
    assert "signature verification failed" in result["logs"][0]


@pytest.mark.asyncio
async def test_container_patcher_success_includes_digest_and_build_id():
    patcher = ContainerPatcher()
    result = await patcher.execute_patch(
        "repo/app",
        {
            "target_package": "nginx",
            "target_version": "1.25",
            "dockerfile_content": "FROM nginx:1.0\n",
        },
        {},
    )
    assert result["status"] == "SUCCESS"
    assert result["digest"].startswith("sha256:")
    assert result["build_id"]


# ---- Canary + Redlock (Pillar 8) ----


def test_redlock_acquire_release_in_process():
    lock = Redlock("test-lock", ttl_seconds=30)
    assert lock.acquire() is True
    assert lock.acquire() is True  # same instance re-acquire returns True (held)
    lock.release()


def test_redlock_contention_blocks_second_holder():
    first = Redlock("contended-lock")
    second = Redlock("contended-lock")
    assert first.acquire() is True
    assert second.acquire() is False
    first.release()
    assert second.acquire() is True
    second.release()


def test_canary_next_ring_hosts_scaled_by_fraction():
    hosts = [f"host-{i}" for i in range(20)]
    deploy = CanaryDeployment(20, hosts)
    ring0 = deploy.next_ring(0)
    assert ring0["fraction"] == 0.05
    assert len(ring0["hosts"]) == 1
    ring2 = deploy.next_ring(2)
    assert ring2["fraction"] == 0.70
    assert len(ring2["hosts"]) == 14


def test_canary_next_ring_exhausts_at_100_percent():
    deploy = CanaryDeployment(10, [])
    assert deploy.next_ring(3)["fraction"] == 1.0
    assert deploy.next_ring(4) is None


@pytest.mark.asyncio
async def test_canary_roll_forward_deploys_ring_and_halts_on_failure():
    executor = AsyncMock()
    executor.execute_patch.return_value = {"status": "SUCCESS"}
    deploy = CanaryDeployment(4, [f"host-{i}" for i in range(4)])
    result = await deploy.roll_forward(executor, {"target_package": "curl"}, {})
    assert result["status"] == "RING_DEPLOYED"
    halted = await deploy.roll_forward(executor, {}, {}, verify_failed=True)
    assert halted["status"] == "HALTED"


@pytest.mark.asyncio
async def test_orchestration_engine_canary_returns_canary_plan():
    engine = OrchestrationEngine()
    result = await engine.run_remediation(
        "host-1",
        "linux",
        [{"method": "apt", "target_package": "openssl"}],
        canary_rings=True,
        available_hosts=["host-1", "host-2"],
    )
    assert result["overall_status"] == "CANARY"
    assert result["canary"]["fraction"] == 0.05


@pytest.mark.asyncio
async def test_orchestration_engine_redlock_blocks_second_job():
    engine = OrchestrationEngine()
    first_lock = Redlock("nexora:lock:host-a", ttl_seconds=60)
    assert first_lock.acquire()
    result = await engine.run_remediation(
        "host-a", "linux", [{"method": "apt", "target_package": "x"}]
    )
    assert result["overall_status"] == "BLOCKED"
    first_lock.release()


# ---- Secrets Manager (Pillar 9) ----


def test_in_process_secrets_roundtrip():
    secrets = InProcessSecrets()
    secrets.store_local("db-creds", {"username": "nexora", "password": "s3cret"})
    assert secrets.get_secret("db-creds") == {"username": "nexora", "password": "s3cret"}


def test_in_process_secrets_missing_raises():
    secrets = InProcessSecrets()
    with pytest.raises(KeyError):
        secrets.get_secret("missing")


def test_vault_backend_missing_client_raises():
    secrets = SecretsManager(backend="vault", vault_addr="http://vault:8200", vault_token="token")
    with pytest.raises(Exception):
        secrets.get_secret("foo")


def test_unsupported_backend_raises():
    secrets = SecretsManager(backend="nosuch")
    with pytest.raises(ValueError):
        secrets.get_secret("foo")


# ---- Rescan Verifier (Pillar 10) ----


def test_rescan_verify_passes_when_cve_absent_after():
    verifier = RescanVerifier()
    before = [{"cve_id": "CVE-2026-0001"}]
    after = []
    outcome = verifier.evaluate(before, after, ["CVE-2026-0001"])
    assert outcome["verified"] is True
    assert outcome["still_present"] == []


def test_rescan_verify_fails_when_cve_still_present():
    verifier = RescanVerifier()
    after = [{"cve_id": "CVE-2026-0001"}]
    outcome = verifier.evaluate([], after, ["CVE-2026-0001"])
    assert outcome["verified"] is False
    assert outcome["still_present"] == ["CVE-2026-0001"]


@pytest.mark.asyncio
async def test_rescan_verify_retries_until_clean():
    class Scanner:
        def __init__(self):
            self.calls = 0

        async def fetch_remote_scan(self, asset_identifier, credentials):
            self.calls += 1
            return [] if self.calls > 1 else [{"cve_id": "CVE-2026-0001"}]

    scanner = Scanner()
    verifier = RescanVerifier(retry_attempts=3)
    outcome = await verifier.verify(scanner, "srv-1", {}, ["CVE-2026-0001"], [])
    assert outcome["verified"] is True
    assert outcome["attempts"] == 2


@pytest.mark.asyncio
async def test_rescan_verify_exhausts_retries():
    class Scanner:
        async def fetch_remote_scan(self, asset_identifier, credentials):
            return [{"cve_id": "CVE-2026-0001"}]

    verifier = RescanVerifier(retry_attempts=3)
    outcome = await verifier.verify(Scanner(), "srv-1", {}, ["CVE-2026-0001"], [])
    assert outcome["verified"] is False
    assert outcome["attempts"] == 3


# ---- Registry integration ----


def test_registry_includes_new_adapters():
    assert "ssm" in ExecutionAdapterRegistry.supported_methods()
    assert "docker_image" in ExecutionAdapterRegistry.supported_methods()


# ---- CLI (Pillar 12) ----


def test_cli_scan_report_outputs_findings(capsys):
    rc = main(
        ["scan", "report", "--asset", "srv-1", "--items-json", '[{"cve_id": "CVE-2026-0001"}]']
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "srv-1" in out
    assert "CVE-2026-0001" in out


def test_cli_rescan_verify_clean(capsys):
    rc = main(
        [
            "scan",
            "rescan-verify",
            "--asset",
            "srv-1",
            "--before-json",
            '[{"cve_id": "CVE-2026-0001"}]',
            "--after-json",
            "[]",
            "--target-cves",
            '["CVE-2026-0001"]',
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert '"verified": true' in out


def test_cli_rescan_verify_still_vulnerable_returns_error(capsys):
    rc = main(
        [
            "scan",
            "rescan-verify",
            "--asset",
            "srv-1",
            "--after-json",
            '[{"cve_id": "CVE-2026-0001"}]',
            "--target-cves",
            '["CVE-2026-0001"]',
        ]
    )
    out = capsys.readouterr().out
    assert rc == 2
    assert '"verified": false' in out
