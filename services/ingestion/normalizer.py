from typing import List, Dict, Any, Type
from services.ingestion.base_plugin import BaseScannerPlugin
from services.ingestion.qualys_connector import QualysConnector
from services.ingestion/rapid7_connector import Rapid7Connector
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

    def register_plugin(self, plugin: BaseScannerPlugin) -> None:
        self._plugins[plugin.plugin_name.lower()] = plugin

    async def normalize_scan(self, scanner_type: str, raw_payload: Dict[str, Any]) -> List[VulnerabilityItem]:
        plugin_key = scanner_type.lower()
        if plugin_key not in self._plugins:
            # Fallback to trivy parser if unmapped
            plugin = self._plugins.get("trivy", TrivyParser())
        else:
            plugin = self._plugins[plugin_key]

        return await plugin.parse_payload(raw_payload)
