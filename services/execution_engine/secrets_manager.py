"""
Secrets Manager (Blueprint Pillar 9).

Retrieves execution credentials from HashiCorp Vault or AWS Secrets Manager.
Provides an in-process fallback so test environments and local execution stay
hermetic. All secrets are retained only in memory and never logged.
"""

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class SecretsManager:
    """Credential fetch abstraction over Vault / AWS Secrets Manager."""

    def __init__(
        self,
        backend: str = "in_process",
        vault_addr: Optional[str] = None,
        vault_token: Optional[str] = None,
        aws_region: Optional[str] = None,
    ) -> None:
        self.backend = backend
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self.aws_region = aws_region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self._memory: Dict[str, Dict[str, Any]] = {}
        self._vault_client = None
        self._aws_client = None

    def store_local(self, secret_name: str, payload: Dict[str, Any]) -> None:
        """Seed an in-process secret (used in tests and local execution)."""
        self._memory[secret_name] = payload

    def _get_vault(self):
        if self._vault_client is None:
            import hvac

            self._vault_client = hvac.Client(url=self.vault_addr, token=self.vault_token)
        return self._vault_client

    def _get_aws(self):
        if self._aws_client is None:
            import boto3

            self._aws_client = boto3.client("secretsmanager", region_name=self.aws_region)
        return self._aws_client

    def get_secret(self, secret_name: str) -> Dict[str, Any]:
        """Return a secret dict, resolving via the configured backend."""
        if self.backend == "in_process":
            secret = self._memory.get(secret_name)
            if secret is None:
                raise KeyError(f"Secret '{secret_name}' not found in in-process store")
            return dict(secret)

        if self.backend == "vault":
            client = self._get_vault()
            response = client.secrets.kv.v2.read_secret_version(path=secret_name)
            return dict(response["data"]["data"])

        if self.backend == "aws":
            client = self._get_aws()
            response = client.get_secret_value(SecretId=secret_name)
            import json

            return json.loads(response["SecretString"])

        raise ValueError(f"Unsupported secrets backend: {self.backend}")


class InProcessSecrets(SecretsManager):
    """Convenience wrapper defaulting to the hermetic in-process backend."""

    def __init__(self) -> None:
        super().__init__(backend="in_process")
