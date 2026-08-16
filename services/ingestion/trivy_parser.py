from typing import List, Dict, Any
from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem

class TrivyParser(BaseScannerPlugin):
    """
    Trivy Container & OS Scan JSON Report Parser Plugin
    """

    @property
    def plugin_name(self) -> str:
        return "trivy"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        results = raw_data.get("Results", [])
        for result in results:
            vulns = result.get("Vulnerabilities", [])
            for item in vulns:
                cve = item.get("VulnerabilityID", "CVE-UNKNOWN")
                pkg = item.get("PkgName", "unknown-package")
                inst_ver = item.get("InstalledVersion", "0.0.0")
                fix_ver = item.get("FixedVersion", None)
                
                # Extract CVSS score
                cvss_data = item.get("CVSS", {})
                cvss_score = 0.0
                if "nvd" in cvss_data:
                    cvss_score = float(cvss_data["nvd"].get("V3Score", cvss_data["nvd"].get("V2Score", 0.0)))
                elif "redhat" in cvss_data:
                    cvss_score = float(cvss_data["redhat"].get("V3Score", 0.0))

                vulnerabilities.append(
                    VulnerabilityItem(
                        cve_id=cve,
                        package_name=pkg,
                        installed_version=inst_ver,
                        fixed_version=fix_ver,
                        cvss_score=cvss_score,
                        epss_score=0.0,
                        is_known_exploited=False,
                        scanner_source=self.plugin_name,
                        raw_metadata=item
                    )
                )
        return vulnerabilities

    async def fetch_remote_scan(self, asset_identifier: str, credentials: Dict[str, Any]) -> List[VulnerabilityItem]:
        return []
