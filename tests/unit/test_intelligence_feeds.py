import pytest

from services.ingestion.cisa_kev import CISAKEVFeed
from services.ingestion.epss_feed import EPSSFeed
from services.ingestion.nvd_feed import NVDFeed


class TestNVDFeed:
    def test_normalize_cve_extracts_metrics(self):
        raw_cve = {
            "id": "CVE-2024-3094",
            "descriptions": [{"lang": "en", "value": "XZ Utils backdoor"}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "version": "3.1"}}]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-787"}]}],
            "published": "2024-03-29T00:00:00Z",
        }
        result = NVDFeed._normalize_cve(raw_cve)
        assert result["cve_id"] == "CVE-2024-3094"
        assert result["cvss_score"] == 10.0
        assert result["cvss_version"] == "3.1"
        assert result["cwe_ids"] == ["CWE-787"]
        assert "backdoor" in result["description"]

    def test_normalize_cve_falls_back_across_metric_versions(self):
        raw_cve = {
            "id": "CVE-2020-0601",
            "descriptions": [],
            "metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 8.1, "version": "2.0"}}]},
            "weaknesses": [],
        }
        result = NVDFeed._normalize_cve(raw_cve)
        assert result["cvss_score"] == 8.1
        assert result["cvss_version"] == "2.0"

    def test_normalize_cve_handles_empty_metrics(self):
        result = NVDFeed._normalize_cve({"id": "CVE-2024-0000", "metrics": {}})
        assert result["cvss_score"] == 0.0
        assert result["cvss_version"] == ""

    @pytest.mark.asyncio
    async def test_fetch_cve_returns_none_on_network_failure(self, monkeypatch):
        feed = NVDFeed(timeout=0.1)

        async def fake_get(*args, **kwargs):
            raise Exception("network down")

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        result = await feed.fetch_cve("CVE-2024-3094")
        assert result is None


class TestCISAKEVFeed:
    @pytest.mark.asyncio
    async def test_returns_empty_on_network_failure(self, monkeypatch):
        feed = CISAKEVFeed(timeout=0.1)

        async def fake_get(*args, **kwargs):
            raise Exception("network down")

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        catalog = await feed.fetch_catalog()
        assert catalog == []
        assert await feed.is_known_exploited("CVE-2024-3094") is False
        assert await feed.get_kev_detail("CVE-2024-3094") is None

    @pytest.mark.asyncio
    async def test_matches_cve_in_catalog(self, monkeypatch):
        feed = CISAKEVFeed(timeout=0.1)
        fake_catalog = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-3094", "product": "XZ", "vendorProject": "Tukaani"}
            ]
        }

        async def fake_get(*args, **kwargs):
            class FakeResponse:
                status_code = 200

                def json(self):
                    return fake_catalog

            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        assert await feed.is_known_exploited("cve-2024-3094") is True
        detail = await feed.get_kev_detail("CVE-2024-3094")
        assert detail["vendorProject"] == "Tukaani"
        assert await feed.is_known_exploited("CVE-2024-9999") is False


class TestEPSSFeed:
    @pytest.mark.asyncio
    async def test_returns_zero_on_network_failure(self, monkeypatch):
        feed = EPSSFeed(timeout=0.1)

        async def fake_get(*args, **kwargs):
            raise Exception("network down")

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        assert await feed.fetch_score("CVE-2024-3094") == 0.0

    @pytest.mark.asyncio
    async def test_parses_epss_score(self, monkeypatch):
        feed = EPSSFeed(timeout=0.1)

        async def fake_get(*args, **kwargs):
            class FakeResponse:
                status_code = 200

                def json(self):
                    return {"data": [{"cve": "CVE-2024-3094", "epss": 0.975, "percentile": 0.99}]}

            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        assert await feed.fetch_score("CVE-2024-3094") == 0.975
        # Cached on second call
        assert await feed.fetch_score("CVE-2024-3094") == 0.975

    @pytest.mark.asyncio
    async def test_returns_zero_when_no_data(self, monkeypatch):
        feed = EPSSFeed(timeout=0.1)

        async def fake_get(*args, **kwargs):
            class FakeResponse:
                status_code = 200

                def json(self):
                    return {"data": []}

            return FakeResponse()

        monkeypatch.setattr("httpx.AsyncClient.get", fake_get)
        assert await feed.fetch_score("CVE-2024-0000") == 0.0
