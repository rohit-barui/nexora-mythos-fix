from abc import ABC, abstractmethod
from typing import Any, Dict, List

from services.models.domain_schemas import VulnerabilityItem


class BaseScannerPlugin(ABC):
    """
    Abstract base class for all vulnerability scanner plugins
    (Qualys, Rapid7, Nessus, Trivy, Snyk, etc.).
    """

    @property
    @abstractmethod
    def plugin_name(self) -> str:
        """Name of the scanner plugin (e.g. 'qualys', 'rapid7', 'trivy')"""
        pass

    @abstractmethod
    async def parse_payload(self, raw_data: Any) -> List[VulnerabilityItem]:
        """
        Parse raw scanner output (JSON/XML/Dict) into standardized VulnerabilityItem objects.
        """
        pass

    @abstractmethod
    async def fetch_remote_scan(
        self, asset_identifier: str, credentials: Dict[str, Any]
    ) -> List[VulnerabilityItem]:
        """
        Fetch scan results directly from scanner API endpoints.
        """
        pass
