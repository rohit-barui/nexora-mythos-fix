from typing import Dict, Type

from services.execution_engine.apk_adapter import ApkAdapter
from services.execution_engine.apt_adapter import AptAdapter
from services.execution_engine.base import BaseExecutionAdapter
from services.execution_engine.dnf_adapter import DnfAdapter
from services.execution_engine.k8s_adapter import KubernetesAdapter
from services.execution_engine.kernel_hardening_adapter import KernelHardeningAdapter
from services.execution_engine.virtual_patch_adapter import VirtualPatchAdapter
from services.execution_engine.winrm_adapter import WinRMAdapter


class ExecutionAdapterRegistry:
    """
    Micro-kernel plugin registry mapping execution methods to adapters.
    New adapters register here without touching core execution logic.
    """

    ADAPTERS: Dict[str, Type[BaseExecutionAdapter]] = {
        "apt": AptAdapter,
        "dnf": DnfAdapter,
        "apk": ApkAdapter,
        "winrm": WinRMAdapter,
        "k8s_image": KubernetesAdapter,
        "waf_rule": VirtualPatchAdapter,
        "sysctl": KernelHardeningAdapter,
    }

    @classmethod
    def get(cls, method: str) -> BaseExecutionAdapter:
        if method not in cls.ADAPTERS:
            raise KeyError(
                f"No execution adapter registered for method '{method}'. "
                f"Available: {sorted(cls.ADAPTERS)}"
            )
        return cls.ADAPTERS[method]()

    @classmethod
    def supported_methods(cls) -> list:
        return sorted(cls.ADAPTERS)
