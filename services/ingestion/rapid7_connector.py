from typing import Any, Dict, List

from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem


class Rapid7Connector(BaseScannerPlugin):
    """
    Rapid7 InsightVM & Nexpose Ingestor Plugin
    """

    @property
    def plugin_name(self) -> str:
        return "rapid7"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        vulns = raw_data.get("vulnerabilities", raw_data.get("resources", []))
        for item in vulns:
            cve = item.get("cve", item.get("cve_id", "CVE-UNKNOWN"))
            pkg = item.get("software", item.get("package", "unknown-package"))
            inst_ver = item.get("installed_version", "0.0.0")
            fix_ver = item.get("solution", {}).get("fixed_version", item.get("fixed_version"))
            cvss = float(item.get("cvss", {}).get("score", item.get("cvss_score", 0.0)))
            epss = float(item.get("epss", 0.0))
            is_kev = bool(item.get("exploited_in_wild", False))

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
        return []
