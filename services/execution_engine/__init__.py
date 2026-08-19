"""
Nexora Multi-OS Execution Adapters, Snapshot Engine & Patch Executor
"""

from services.execution_engine.apk_adapter import ApkAdapter
from services.execution_engine.apt_adapter import AptAdapter
from services.execution_engine.aws_ssm_adapter import AWSSSMAdapter
from services.execution_engine.base import BaseExecutionAdapter
from services.execution_engine.container_patcher import ContainerPatcher
from services.execution_engine.dnf_adapter import DnfAdapter
from services.execution_engine.executor import PatchExecutor
from services.execution_engine.k8s_adapter import KubernetesAdapter
from services.execution_engine.kernel_hardening_adapter import KernelHardeningAdapter
from services.execution_engine.registry import ExecutionAdapterRegistry
from services.execution_engine.secrets_manager import InProcessSecrets, SecretsManager
from services.execution_engine.snapshot_manager import PrePatchSnapshotManager
from services.execution_engine.virtual_patch_adapter import VirtualPatchAdapter
from services.execution_engine.winrm_adapter import WinRMAdapter

__all__ = [
    "ApkAdapter",
    "AptAdapter",
    "AWSSSMAdapter",
    "BaseExecutionAdapter",
    "ContainerPatcher",
    "DnfAdapter",
    "ExecutionAdapterRegistry",
    "InProcessSecrets",
    "KernelHardeningAdapter",
    "KubernetesAdapter",
    "PatchExecutor",
    "PrePatchSnapshotManager",
    "SecretsManager",
    "VirtualPatchAdapter",
    "WinRMAdapter",
]
