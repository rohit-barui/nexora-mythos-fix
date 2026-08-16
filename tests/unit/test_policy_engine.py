import pytest

from services.policy_engine.client import OPAPolicyClient


class TestOPAPolicyClientFallback:
    @pytest.mark.asyncio
    async def test_allowed_when_no_violations(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 5},
            plan_payload={"actions": [{"target_package": "openssl"}]},
            has_escalation_approval=False,
            current_hour=10,
        )
        assert result["allowed"] is True
        assert result["violations"] == []
        assert result["mode"] == "local_fallback"

    @pytest.mark.asyncio
    async def test_production_blocked_during_business_hours(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "production", "criticality_score": 5},
            plan_payload={"actions": [{"target_package": "openssl"}]},
            has_escalation_approval=False,
            current_hour=12,
        )
        assert result["allowed"] is False
        assert "business hours" in result["violations"][0]

    @pytest.mark.asyncio
    async def test_production_allowed_outside_business_hours(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "production", "criticality_score": 5},
            plan_payload={"actions": [{"target_package": "openssl"}]},
            has_escalation_approval=False,
            current_hour=22,
        )
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_critical_restart_requires_escalation(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 8},
            plan_payload={"actions": [{"target_package": "nginx", "restart_required": True}]},
            has_escalation_approval=False,
            current_hour=10,
        )
        assert result["allowed"] is False
        assert "approval escalation" in result["violations"][0]

    @pytest.mark.asyncio
    async def test_critical_restart_allowed_with_escalation(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 8},
            plan_payload={"actions": [{"target_package": "nginx", "restart_required": True}]},
            has_escalation_approval=True,
            current_hour=10,
        )
        assert result["allowed"] is True

    @pytest.mark.asyncio
    async def test_missing_target_package_violation(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 5},
            plan_payload={"actions": [{"target_package": ""}]},
            has_escalation_approval=False,
            current_hour=10,
        )
        assert result["allowed"] is False
        assert "missing target_package" in result["violations"][0]

    @pytest.mark.asyncio
    async def test_kernel_update_requires_escalation(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 5},
            plan_payload={"actions": [{"target_package": "linux-image-generic"}]},
            has_escalation_approval=False,
            current_hour=10,
        )
        assert result["require_escalation"] is True

    @pytest.mark.asyncio
    async def test_high_criticality_requires_escalation(self):
        client = OPAPolicyClient()
        result = client._evaluate_locally(
            asset_info={"environment": "staging", "criticality_score": 9},
            plan_payload={"actions": [{"target_package": "openssl"}]},
            has_escalation_approval=False,
            current_hour=10,
        )
        assert result["require_escalation"] is True


class TestOPAPolicyClientRemote:
    @pytest.mark.asyncio
    async def test_parses_allowed_result(self, monkeypatch):
        client = OPAPolicyClient(opa_url="http://opa:8181")

        async def fake_post(self, *args, **kwargs):
            class FakeResponse:
                status_code = 200

                def json(self):
                    return {
                        "result": {"allow": True, "require_escalation": False, "violations": []}
                    }

            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
        result = await client.evaluate_plan({"environment": "prod"}, {"actions": []})
        assert result["allowed"] is True
        assert "mode" not in result  # remote path does not set mode

    @pytest.mark.asyncio
    async def test_parses_denied_result(self, monkeypatch):
        client = OPAPolicyClient(opa_url="http://opa:8181")

        async def fake_post(self, *args, **kwargs):
            class FakeResponse:
                status_code = 200

                def json(self):
                    return {
                        "result": {
                            "allow": False,
                            "require_escalation": True,
                            "violations": ["Business hours"],
                        }
                    }

            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
        result = await client.evaluate_plan({"environment": "prod"}, {"actions": []})
        assert result["allowed"] is False
        assert result["require_escalation"] is True
        assert result["violations"] == ["Business hours"]

    @pytest.mark.asyncio
    async def test_falls_back_locally_on_network_error(self, monkeypatch):
        client = OPAPolicyClient(opa_url="http://opa:8181")

        async def fake_post(self, *args, **kwargs):
            raise Exception("connection refused")

        monkeypatch.setattr("httpx.AsyncClient.post", fake_post)
        result = await client.evaluate_plan(
            {"environment": "production", "criticality_score": 5},
            {"actions": [{"target_package": "openssl"}]},
        )
        assert result["mode"] == "local_fallback"
        assert "allowed" in result


class TestRegoStructure:
    def test_rego_files_exist(self):
        files = OPAPolicyClient.load_rego_policies()
        names = [f.name for f in files]
        assert "remediation_rules.rego" in names
        assert "safety_checks.rego" in names
        assert "virtual_patch_rules.rego" in names

    def test_rego_structure_valid(self):
        result = OPAPolicyClient.validate_rego_syntax_structure()
        assert result["valid"] is True
        assert result["missing_packages"] == []
        assert result["missing_rules"] == []
        assert "package nexora.remediation" in result["policy_content"]

    def test_rego_dir_missing_raises(self, monkeypatch):
        monkeypatch.setattr(
            OPAPolicyClient, "REGO_DIR", OPAPolicyClient.REGO_DIR.parent / "does-not-exist"
        )
        with pytest.raises(FileNotFoundError):
            OPAPolicyClient.load_rego_policies()
