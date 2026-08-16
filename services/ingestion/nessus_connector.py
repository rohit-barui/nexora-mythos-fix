from typing import Any, Dict, List

from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem


class NessusConnector(BaseScannerPlugin):
    """
    Tenable Nessus / Tenable.io Ingestor Plugin.
    Supports both Tenable.io REST API export payloads (JSON) and parsed .nessus report dicts.
    """

    @property
    def plugin_name(self) -> str:
        return "nessus"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        # Support both wrapped host payloads and flat vulnerability list payloads
        hosts = raw_data.get("hosts", raw_data.get("results", []))
        if isinstance(hosts, dict):
            hosts = hosts.get("hosts", [])
        flat_items = raw_data.get("vulnerabilities", [])
        if isinstance(flat_items, dict):
            flat_items = flat_items.get("vulnerabilities", [])

        entries = []
        for host in hosts:
            entries.extend(host.get("vulnerabilities", host.get("items", [])))
        entries.extend(flat_items)

        for item in entries:
            cve = item.get("cve_id", item.get("cve", "CVE-UNKNOWN"))
            pkg = item.get("package", item.get("plugin_name", "unknown-package"))
            inst_ver = item.get("installed_version", "0.0.0")
            fix_ver = item.get("fixed_version", None)

            cvss_data = item.get("cvss", item.get("cvss3", {}))
            if isinstance(cvss_data, dict):
                cvss_score = float(cvss_data.get("base_score", cvss_data.get("score", 0.0)))
            else:
                cvss_score = float(cvss_data or 0.0)

            epss = float(item.get("epss_score", 0.0))
            is_kev = bool(item.get("is_known_exploited", item.get("exploited_in_wild", False)))

            vulnerabilities.append(
                VulnerabilityItem(
                    cve_id=cve,
                    package_name=pkg,
                    installed_version=inst_ver,
                    fixed_version=fix_ver,
                    cvss_score=cvss_score,
                    epss_score=epss,
                    is_known_exploited=is_kev,
                    scanner_source=self.plugin_name,
                    raw_metadata=item,
                )
            )
        return vulnerabilities

    async def fetch_remote_scan(
        self, asset_identifier: str, credentials: Dict[str, Any]
    ) -> List[VulnerabilityItem]:
        # Simulated API call for Tenable.io endpoint
        return []
