from typing import Any, Dict, List, Optional, Set

import httpx


class CISAKEVFeed:
    """
    CISA Known Exploited Vulnerabilities (KEV) Catalog Client.
    Fetches the authoritative list of actively exploited CVEs.
    """

    CATALOG_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._catalog: List[Dict[str, Any]] = []
        self._cve_set: Optional[Set[str]] = None

    async def fetch_catalog(self) -> List[Dict[str, Any]]:
        """
        Fetch and cache the CISA KEV catalog.
        Returns the list of vulnerability records, or [] on network failure.
        """
        if self._catalog:
            return self._catalog
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.CATALOG_URL)
                if response.status_code != 200:
                    return []
                data = response.json()
                self._catalog = data.get("vulnerabilities", [])
                self._cve_set = {v.get("cveID", "") for v in self._catalog}
        except Exception:
            self._catalog = []
            self._cve_set = set()
        return self._catalog

    async def is_known_exploited(self, cve_id: str) -> bool:
        """Returns True if the CVE is in the CISA KEV catalog."""
        if self._cve_set is None:
            await self.fetch_catalog()
        return cve_id.upper() in (self._cve_set or set())

    async def get_kev_detail(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Returns the KEV catalog record for a CVE, or None."""
        if self._cve_set is None:
            await self.fetch_catalog()
        for v in self._catalog:
            if v.get("cveID", "").upper() == cve_id.upper():
                return v
        return None

    async def enrich_vulnerability(self, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """Set is_known_exploited on a vulnerability dict from the KEV catalog."""
        detail = await self.get_kev_detail(vuln.get("cve_id", ""))
        vuln["is_known_exploited"] = bool(detail)
        if detail:
            vuln["raw_metadata"] = {**vuln.get("raw_metadata", {}), "cisa_kev": detail}
        return vuln
