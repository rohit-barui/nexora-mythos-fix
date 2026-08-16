from typing import Any, Dict, List

from services.ingestion.base_plugin import BaseScannerPlugin
from services.ingestion.crowdstrike_connector import CrowdStrikeConnector
from services.ingestion.nessus_connector import NessusConnector
from services.ingestion.qualys_connector import QualysConnector
from services.ingestion.rapid7_connector import Rapid7Connector
from services.ingestion.snyk_connector import SnykConnector
from services.ingestion.trivy_parser import TrivyParser
from services.models.domain_schemas import VulnerabilityItem


class IngestionNormalizer:
    """
    Ingestion Core & Registry for Scanner Connectors.
    Parses and normalizes heterogeneous security scan payloads into standardized VulnerabilityItems.
    """

    def __init__(self):
        self._plugins: Dict[str, BaseScannerPlugin] = {}
        self.register_plugin(QualysConnector())
        self.register_plugin(Rapid7Connector())
        self.register_plugin(TrivyParser())
        self.register_plugin(NessusConnector())
        self.register_plugin(CrowdStrikeConnector())
        self.register_plugin(SnykConnector())

    def register_plugin(self, plugin: BaseScannerPlugin) -> None:
        self._plugins[plugin.plugin_name.lower()] = plugin

    @property
    def registered_plugins(self) -> List[str]:
        """Return the list of registered scanner plugin names."""
        return sorted(self._plugins.keys())

    async def normalize_scan(
        self, scanner_type: str, raw_payload: Dict[str, Any]
    ) -> List[VulnerabilityItem]:
        plugin_key = scanner_type.lower()
        if plugin_key not in self._plugins:
            # Fallback to trivy parser if unmapped
            plugin = self._plugins.get("trivy", TrivyParser())
        else:
            plugin = self._plugins[plugin_key]

        return await plugin.parse_payload(raw_payload)
