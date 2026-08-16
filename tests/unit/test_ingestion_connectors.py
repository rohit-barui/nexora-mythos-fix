import pytest

from services.ingestion.crowdstrike_connector import CrowdStrikeConnector
from services.ingestion.nessus_connector import NessusConnector
from services.ingestion.normalizer import IngestionNormalizer
from services.ingestion.qualys_connector import QualysConnector
from services.ingestion.rapid7_connector import Rapid7Connector
from services.ingestion.snyk_connector import SnykConnector


@pytest.fixture
def normalizer():
    return IngestionNormalizer()


@pytest.mark.asyncio
async def test_normalizer_registers_all_scanner_plugins(normalizer):
    plugins = normalizer.registered_plugins
    assert "qualys" in plugins
    assert "rapid7" in plugins
    assert "trivy" in plugins
    assert "nessus" in plugins
    assert "crowdstrike" in plugins
    assert "snyk" in plugins


@pytest.mark.asyncio
async def test_normalizer_falls_back_to_trivy_for_unknown_scanner(normalizer):
    raw = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "libssl3",
                        "InstalledVersion": "3.0.2",
                        "FixedVersion": "3.0.3",
                        "CVSS": {"nvd": {"V3Score": 7.5}},
                    }
                ]
            }
        ]
    }
    items = await normalizer.normalize_scan("unknown_scanner", raw)
    assert len(items) == 1
    assert items[0].scanner_source == "trivy"


@pytest.mark.asyncio
async def test_nessus_connector_parses_hosts_payload():
    connector = NessusConnector()
    raw = {
        "hosts": [
            {
                "vulnerabilities": [
                    {
                        "cve_id": "CVE-2021-44228",
                        "package": "log4j-core",
                        "installed_version": "2.14.1",
                        "fixed_version": "2.17.0",
                        "cvss": {"base_score": 10.0},
                        "epss_score": 0.97,
                        "is_known_exploited": True,
                    }
                ]
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "CVE-2021-44228"
    assert item.cvss_score == 10.0
    assert item.epss_score == 0.97
    assert item.is_known_exploited is True
    assert item.scanner_source == "nessus"


@pytest.mark.asyncio
async def test_nessus_connector_parses_scalar_cvss():
    connector = NessusConnector()
    raw = {
        "vulnerabilities": [
            {
                "cve": "CVE-2020-0601",
                "plugin_name": "MS16-xxx",
                "installed_version": "1.0.0",
                "cvss": 8.1,
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert items[0].cvss_score == 8.1


@pytest.mark.asyncio
async def test_crowdstrike_connector_parses_resources():
    connector = CrowdStrikeConnector()
    raw = {
        "resources": [
            {
                "cve": "CVE-2023-44487",
                "product": "nginx",
                "installed_version": "1.24.0",
                "fixed_version": "1.24.1",
                "cvss": {"base_score": 7.5},
                "known_exploited": True,
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "CVE-2023-44487"
    assert item.package_name == "nginx"
    assert item.cvss_score == 7.5
    assert item.is_known_exploited is True


@pytest.mark.asyncio
async def test_snyk_connector_parses_vulnerabilities():
    connector = SnykConnector()
    raw = {
        "vulnerabilities": [
            {
                "id": "SNYK-JS-LODASH-590103",
                "packageName": "lodash",
                "version": "4.17.20",
                "cvssScore": 7.4,
                "exploit": "Proof of Concept",
                "fix": {"upgradePaths": ["lodash@4.17.21"]},
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "SNYK-JS-LODASH-590103"
    assert item.package_name == "lodash"
    assert item.cvss_score == 7.4
    assert item.is_known_exploited is True
    assert item.fixed_version == "lodash@4.17.21"


@pytest.mark.asyncio
async def test_snyk_connector_no_exploit_not_kev():
    connector = SnykConnector()
    raw = {
        "vulnerabilities": [
            {
                "id": "CVE-2024-1000",
                "packageName": "foo",
                "version": "1.0.0",
                "cvssScore": 5.0,
                "exploit": "Not Defined",
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert items[0].is_known_exploited is False


@pytest.mark.asyncio
async def test_qualys_connector_parses_detections():
    connector = QualysConnector()
    raw = {
        "qualys_vm_detection": {
            "detections": [
                {
                    "cve_id": "CVE-2021-44228",
                    "qid_title": "Apache Log4j RCE",
                    "installed_version": "2.14.1",
                    "fixed_version": "2.17.0",
                    "cvss_base": 10.0,
                    "epss_score": 0.97,
                    "is_known_exploited": True,
                }
            ]
        }
    }
    items = await connector.parse_payload(raw)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "CVE-2021-44228"
    assert item.package_name == "Apache Log4j RCE"
    assert item.cvss_score == 10.0
    assert item.epss_score == 0.97
    assert item.is_known_exploited is True
    assert item.scanner_source == "qualys"


@pytest.mark.asyncio
async def test_qualys_connector_parses_flat_detections():
    connector = QualysConnector()
    raw = {
        "detections": [{"cve": "CVE-2024-9999", "package": "libssl3", "installed_version": "3.0.2"}]
    }
    items = await connector.parse_payload(raw)
    assert items[0].cve_id == "CVE-2024-9999"
    assert items[0].package_name == "libssl3"
    assert items[0].cvss_score == 0.0


@pytest.mark.asyncio
async def test_rapid7_connector_parses_vulnerabilities():
    connector = Rapid7Connector()
    raw = {
        "vulnerabilities": [
            {
                "cve": "CVE-2023-44487",
                "software": "nginx",
                "installed_version": "1.24.0",
                "solution": {"fixed_version": "1.25.0"},
                "cvss": {"score": 7.5},
                "exploited_in_wild": True,
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "CVE-2023-44487"
    assert item.package_name == "nginx"
    assert item.fixed_version == "1.25.0"
    assert item.cvss_score == 7.5
    assert item.is_known_exploited is True
    assert item.scanner_source == "rapid7"


@pytest.mark.asyncio
async def test_rapid7_connector_parses_resources_fallback():
    connector = Rapid7Connector()
    raw = {
        "resources": [
            {
                "cve_id": "CVE-2024-1001",
                "package": "curl",
                "installed_version": "8.0.0",
                "cvss_score": 6.5,
            }
        ]
    }
    items = await connector.parse_payload(raw)
    assert items[0].cve_id == "CVE-2024-1001"
    assert items[0].cvss_score == 6.5
