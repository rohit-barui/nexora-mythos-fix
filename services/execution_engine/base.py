from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseExecutionAdapter(ABC):
    """
    Abstract Interface for Deterministic Multi-OS Execution Adapters
    """

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Name of the adapter (e.g. 'apt', 'dnf', 'winrm', 'k8s')"""
        pass

    @abstractmethod
    async def dry_run(self, target_host: str, action: Dict[str, Any]) -> List[str]:
        """
        Generate dry-run command list without making state changes.
        """
        pass

    @abstractmethod
    async def execute_patch(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute deterministic, idempotent patch command set.
        """
        pass

    @abstractmethod
    async def execute_rollback(
        self, target_host: str, action: Dict[str, Any], credentials: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute rollback command set if post-patch verification fails.
        """
        pass
