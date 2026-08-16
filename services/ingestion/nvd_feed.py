from typing import Any, Dict, Optional

import httpx


class NVDFeed:
    """
    NVD API v2.0 Client.
    Fetches live CVE data including CVSS v3.1/v4.0 scores and CPE 2.3 matching.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout

    async def fetch_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE detail from NVD API v2.0.
        Returns a normalized dict with cvss metrics or None if unreachable/not found.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.BASE_URL, params={"cveId": cve_id})
                if response.status_code != 200:
                    return None
                data = response.json()
                if not isinstance(data, dict):
                    return None
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return None
                cve_obj = vulns[0].get("cve", {})
                return self._normalize_cve(cve_obj)
        except Exception:
            return None

    @staticmethod
    def _normalize_cve(cve_obj: Dict[str, Any]) -> Dict[str, Any]:
        cve_id = cve_obj.get("id", "CVE-UNKNOWN")
        descriptions = cve_obj.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        metrics = cve_obj.get("metrics", {})
        cvss_score = 0.0
        cvss_version = ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = float(cvss_data.get("baseScore", 0.0))
                cvss_version = cvss_data.get("version", "")
                break

        weaknesses = cve_obj.get("weaknesses", [])
        cwe_ids = []
        for w in weaknesses:
            for desc in w.get("description", []):
                if desc.get("lang") == "en":
                    cwe_ids.append(desc.get("value", ""))

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "cwe_ids": cwe_ids,
            "published": cve_obj.get("published"),
            "last_modified": cve_obj.get("lastModified"),
        }

    async def enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich an existing vulnerability dict with NVD CVSS data if missing.
        """
        cve_id = vuln.get("cve_id", "CVE-UNKNOWN")
        detail = await self.fetch_cve(cve_id)
        if detail and (not vuln.get("cvss_score") or vuln.get("cvss_score") == 0.0):
            vuln["cvss_score"] = detail["cvss_score"]
            vuln["raw_metadata"] = {**vuln.get("raw_metadata", {}), "nvd": detail}
        return vuln
