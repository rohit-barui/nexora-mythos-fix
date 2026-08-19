import pytest

from services.execution_engine.apk_adapter import ApkAdapter
from services.execution_engine.executor import PatchExecutor
from services.execution_engine.k8s_adapter import KubernetesAdapter
from services.execution_engine.kernel_hardening_adapter import KernelHardeningAdapter
from services.execution_engine.registry import ExecutionAdapterRegistry
from services.execution_engine.snapshot_manager import PrePatchSnapshotManager
from services.execution_engine.winrm_adapter import WinRMAdapter


def test_registry_resolves_all_methods():
    supported = ExecutionAdapterRegistry.supported_methods()
    assert supported == [
        "apk",
        "apt",
        "dnf",
        "docker_image",
        "k8s_image",
        "ssm",
        "sysctl",
        "waf_rule",
        "winrm",
    ]
    for method in supported:
        adapter = ExecutionAdapterRegistry.get(method)
        assert adapter is not None


def test_registry_unknown_method_raises():
    with pytest.raises(KeyError, match="No execution adapter registered"):
        ExecutionAdapterRegistry.get("nope")


@pytest.mark.asyncio
async def test_apk_adapter_dry_run_and_patch():
    adapter = ApkAdapter()
    cmds = await adapter.dry_run(
        "alpine-01", {"target_package": "openssl", "target_version": "3.0.3"}
    )
    assert "apk add --upgrade openssl=3.0.3 --simulate" in cmds[0]
    result = await adapter.execute_patch("alpine-01", {"target_package": "openssl"}, {})
    assert result["status"] == "SUCCESS"
    assert "apk add --upgrade openssl" in result["executed_command"]
    rollback = await adapter.execute_rollback(
        "alpine-01", {"target_package": "openssl", "installed_version": "3.0.2"}, {}
    )
    assert rollback["status"] == "ROLLED_BACK"
    assert "openssl=3.0.2" in rollback["executed_command"]


@pytest.mark.asyncio
async def test_k8s_adapter_rollout():
    adapter = KubernetesAdapter()
    result = await adapter.execute_patch(
        "cluster-01", {"target_package": "api-server", "target_version": "v1.2.3"}, {}
    )
    assert result["status"] == "SUCCESS"
    assert "set image deployment/api-server" in result["executed_command"]
    rollback = await adapter.execute_rollback("cluster-01", {"target_package": "api-server"}, {})
    assert "rollout undo" in rollback["executed_command"]


@pytest.mark.asyncio
async def test_kernel_hardening_adapter():
    adapter = KernelHardeningAdapter()
    result = await adapter.execute_patch("app-01", {"target_package": "kernel.kptr_restrict"}, {})
    assert result["status"] == "SUCCESS"
    assert result["hardening_params"] == {"kernel.kptr_restrict": "2"}


@pytest.mark.asyncio
async def test_winrm_adapter():
    adapter = WinRMAdapter()
    result = await adapter.execute_patch("win-01", {"target_package": "KB5034441"}, {})
    assert result["status"] == "SUCCESS"
    assert "KB5034441" in result["executed_command"]


@pytest.mark.asyncio
async def test_snapshot_manager_creates_and_reverts():
    snap = await PrePatchSnapshotManager.create_snapshot("web-01", "debian")
    assert snap["status"] == "READY"
    assert snap["mechanism"] == "LVM_SNAPSHOT"
    assert snap["snapshot_id"].startswith("snap-")

    win_snap = await PrePatchSnapshotManager.create_snapshot("win-01", "windows")
    assert win_snap["mechanism"] == "VSS_SHADOW_COPY"

    revert = await PrePatchSnapshotManager.revert_snapshot(snap)
    assert revert["status"] == "REVERTED"
    assert revert["snapshot_id"] == snap["snapshot_id"]


@pytest.mark.asyncio
async def test_executor_executes_multiple_actions():
    executor = PatchExecutor()
    result = await executor.execute_plan(
        host="web-01",
        os_type="debian",
        actions=[
            {
                "action_type": "patch",
                "target_package": "openssl",
                "method": "apt",
                "target_version": "3.0.3",
            },
            {
                "action_type": "kernel_hardening",
                "target_package": "kernel.kptr_restrict",
                "method": "sysctl",
            },
        ],
    )
    assert result["overall_status"] == "SUCCESS"
    assert result["action_count"] == 2
    assert all(a["status"] == "SUCCESS" for a in result["actions"])
    assert all(a["snapshot_metadata"]["status"] == "READY" for a in result["actions"])


@pytest.mark.asyncio
async def test_executor_rolls_back_on_verification_failure(monkeypatch):
    executor = PatchExecutor()

    async def fake_verify(action, dry_run_cmds):
        return False

    monkeypatch.setattr(executor, "_verify", fake_verify)
    result = await executor.execute_action(
        host="web-01",
        os_type="debian",
        action={"action_type": "patch", "target_package": "openssl", "method": "apt"},
        credentials={},
    )
    assert result["status"] == "ROLLED_BACK"


@pytest.mark.asyncio
async def test_executor_reports_rolled_back_overall(monkeypatch):
    executor = PatchExecutor()

    async def fake_verify(action, dry_run_cmds):
        return False

    monkeypatch.setattr(executor, "_verify", fake_verify)
    result = await executor.execute_plan(
        host="web-01",
        os_type="debian",
        actions=[{"action_type": "patch", "target_package": "openssl", "method": "apt"}],
    )
    assert result["overall_status"] == "ROLLED_BACK"
