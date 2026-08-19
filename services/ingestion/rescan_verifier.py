"""
Post-Patch Rescan Verifier (Blueprint Pillar 10).

After a remediation job completes, re-scans the affected asset and asserts the
target CVE no longer appears. A configurable tolerance allows brief scanner
propagation delay. Verification failures gate canary ring advancement.
"""

from typing import Any, Dict, List


class RescanVerifier:
    """Verifies vulnerability remediation by comparing pre/post scan results."""

    def __init__(self, retry_attempts: int = 3, tolerance_seconds: int = 0) -> None:
        self.retry_attempts = retry_attempts
        self.tolerance_seconds = tolerance_seconds

    def _seen_cves(self, items: List[Dict[str, Any]]) -> List[str]:
        """Normalize both dict and VulnerabilityItem-shaped inputs to CVE ids."""
        seen = []
        for item in items:
            if isinstance(item, dict):
                cve = item.get("cve_id") or item.get("vulnerability_id")
            else:
                cve = getattr(item, "cve_id", None) or getattr(item, "vulnerability_id", None)
            if cve:
                seen.append(cve)
        return seen

    def evaluate(
        self, before: List[Any], after: List[Any], target_cves: List[str]
    ) -> Dict[str, Any]:
        """Return verification outcome for the given target CVEs."""
        before_ids = set(self._seen_cves(before))
        after_ids = set(self._seen_cves(after))
        still_present = [cve for cve in target_cves if cve in after_ids]
        verified = not still_present
        return {
            "verified": verified,
            "target_cves": target_cves,
            "still_present": still_present,
            "pre_scan_count": len(before_ids),
            "post_scan_count": len(after_ids),
        }

    async def verify(
        self,
        scanner: Any,
        asset_identifier: str,
        credentials: Dict[str, Any],
        target_cves: List[str],
        before_items: List[Any],
    ) -> Dict[str, Any]:
        """Run post-patch rescans with retry until verification passes."""
        attempts = 0
        last = None
        while attempts < self.retry_attempts:
            attempts += 1
            after = await scanner.fetch_remote_scan(asset_identifier, credentials)
            last = self.evaluate(before_items, after, target_cves)
            if last["verified"]:
                last["attempts"] = attempts
                return last
        last["attempts"] = attempts
        return last
