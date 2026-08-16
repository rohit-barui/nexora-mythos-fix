import pytest
from services.execution_engine.apt_adapter import AptAdapter
from services.execution_engine.dnf_adapter import DnfAdapter
from services.execution_engine.virtual_patch_adapter import VirtualPatchAdapter

@pytest.mark.asyncio
async def test_apt_adapter_dry_run():
    adapter = AptAdapter()
    cmds = await adapter.dry_run("web-prod-01", {"target_package": "openssl", "target_version": "3.0.2"})
    assert len(cmds) == 1
    assert "apt-get --simulate install openssl=3.0.2" in cmds[0]

@pytest.mark.asyncio
async def test_dnf_adapter_dry_run():
    adapter = DnfAdapter()
    cmds = await adapter.dry_run("app-prod-01", {"target_package": "curl"})
    assert len(cmds) == 1
    assert "dnf check-update curl" in cmds[0]

@pytest.mark.asyncio
async def test_virtual_patch_adapter():
    adapter = VirtualPatchAdapter()
    result = await adapter.execute_patch("edge-proxy-01", {"target_package": "/api/v1/vulnerable-endpoint"}, {})
    assert result["status"] == "SUCCESS"
    assert "SecRule" in result["waf_rule"]
