from typing import Any, Dict

import httpx


class EPSSFeed:
    """
    FIRST EPSS (Exploit Prediction Scoring System) Client.
    Fetches predictive exploit probability scores (0.0 - 1.0) for CVEs.
    """

    API_URL = "https://api.first.org/data/v1/epss"

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._cache: Dict[str, float] = {}

    async def fetch_score(self, cve_id: str) -> float:
        """
        Fetch EPSS score (0.0 - 1.0) for a CVE.
        Returns 0.0 on network failure or unknown CVE.
        """
        key = cve_id.upper()
        if key in self._cache:
            return self._cache[key]
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.API_URL, params={"cve": cve_id})
                if response.status_code != 200:
                    return 0.0
                data = response.json()
                epss_data = data.get("data", [])
                if not epss_data:
                    return 0.0
                score = float(epss_data[0].get("epss", 0.0))
                self._cache[key] = score
                return score
        except Exception:
            return 0.0

    async def enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Set epss_score on a vulnerability dict from the FIRST EPSS API."""
        score = await self.fetch_score(vuln.get("cve_id", ""))
        vuln["epss_score"] = score
        vuln["raw_metadata"] = {**vuln.get("raw_metadata", {}), "epss": {"epss_score": score}}
        return vuln
