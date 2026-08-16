from typing import Any, Dict, List

from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem


class SnykConnector(BaseScannerPlugin):
    """
    Snyk Open Source / Container Ingestor Plugin.
    Parses Snyk test JSON report payloads.
    """

    @property
    def plugin_name(self) -> str:
        return "snyk"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        results = raw_data.get("vulnerabilities", raw_data.get("issues", []))
        if isinstance(results, dict):
            results = results.get("vulnerabilities", [])
        for item in results:
            cve = item.get("id", item.get("cve_id", "CVE-UNKNOWN"))
            pkg = item.get("packageName", item.get("package", "unknown-package"))
            inst_ver = item.get("version", item.get("installed_version", "0.0.0"))
            fix_ver = None
            if item.get("fix") and item.get("fix").get("upgradePaths"):
                fix_ver = item.get("fix").get("upgradePaths")[0]

            cvss_data = item.get("cvss", item.get("cvssScore", 0.0))
            if isinstance(cvss_data, dict):
                cvss_score = float(cvss_data.get("score", cvss_data.get("base_score", 0.0)))
            else:
                cvss_score = float(cvss_data or 0.0)

            epss = float(item.get("epss_score", 0.0))
            is_kev = bool(
                item.get(
                    "is_known_exploited",
                    item.get("exploit", "Not Defined") not in ["Not Defined", "No Known Exploit"],
                )
            )

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
        # Simulated API call for Snyk API endpoint
        return []
