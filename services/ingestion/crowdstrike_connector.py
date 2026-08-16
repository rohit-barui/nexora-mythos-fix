from typing import Any, Dict, List

from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem


class CrowdStrikeConnector(BaseScannerPlugin):
    """
    CrowdStrike Falcon Spotlight Ingestor Plugin.
    Parses streaming API vulnerability telemetry payloads.
    """

    @property
    def plugin_name(self) -> str:
        return "crowdstrike"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        results = raw_data.get("resources", raw_data.get("vulnerabilities", []))
        if isinstance(results, dict):
            results = results.get("resources", [])
        for item in results:
            cve = item.get("cve", item.get("cve_id", "CVE-UNKNOWN"))
            pkg = item.get("package", item.get("product", "unknown-package"))
            inst_ver = item.get("installed_version", "0.0.0")
            fix_ver = item.get("fixed_version", item.get("remediation", {}).get("fixed_version"))

            cvss = float(item.get("cvss", {}).get("base_score", item.get("cvss_score", 0.0)))
            epss = float(item.get("epss_score", 0.0))
            is_kev = bool(item.get("known_exploited", item.get("is_known_exploited", False)))

            vulnerabilities.append(
                VulnerabilityItem(
                    cve_id=cve,
                    package_name=pkg,
                    installed_version=inst_ver,
                    fixed_version=fix_ver,
                    cvss_score=cvss,
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
        # Simulated API call for CrowdStrike Falcon Spotlight endpoint
        return []
