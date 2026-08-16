from typing import List, Dict, Any
from services.ingestion.base_plugin import BaseScannerPlugin
from services.models.domain_schemas import VulnerabilityItem

class QualysConnector(BaseScannerPlugin):
    """
    Qualys Guard & VMDR API / Report Ingestor Plugin
    """

    @property
    def plugin_name(self) -> str:
        return "qualys"

    async def parse_payload(self, raw_data: Dict[str, Any]) -> List[VulnerabilityItem]:
        vulnerabilities = []
        # Support Qualys JSON payload format
        results = raw_data.get("qualys_vm_detection", {}).get("detections", raw_data.get("detections", []))
        for item in results:
            cve = item.get("cve_id", item.get("cve", "CVE-UNKNOWN"))
            pkg = item.get("package", item.get("qid_title", "unknown-package"))
            inst_ver = item.get("installed_version", "0.0.0")
            fix_ver = item.get("fixed_version", None)
            cvss = float(item.get("cvss_base", item.get("cvss", 0.0)))
            epss = float(item.get("epss_score", 0.0))
            is_kev = bool(item.get("is_known_exploited", False))

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
                    raw_metadata=item
                )
            )
        return vulnerabilities

    async def fetch_remote_scan(self, asset_identifier: str, credentials: Dict[str, Any]) -> List[VulnerabilityItem]:
        # Simulated API call for remote Qualys VMDR endpoint
        return []
