# Nexora Architecture & Security Design Specification

## System Vision
**Nexora (Mythos Fix)** is a governed autonomous remediation control plane designed to ingest vulnerabilities across heterogeneous environments, deterministically compute risk scores, generate structured remediation plans using bounded LLM prompts, validate plans against OPA policy rules, enforce human approval (HITL), and orchestrate patch execution via deterministic adapters and distributed agents.

---

## Technical Architecture Overview

```
                      +---------------------------------------+
                      |         Vulnerability Sources         |
                      | Qualys, Rapid7, Nessus, Trivy, NVD    |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |      Ingestion & Normalizer Core      |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |     Multi-Factor Risk Engine          |
                      |   (CVSS + EPSS + KEV + Criticality)   |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |       Cognitive AI Firewall           |
                      |    (Sanitizer & Prompt Guard)         |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |      LLM Plan Generator Engine        |
                      |     (Pydantic JSON Schema Only)       |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |   Authoritative OPA Policy Engine     |
                      |   (Rego Rules & Gatekeeper)           |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |  HITL Human Approval Queue            |
                      |  (Web Dashboard & MS Teams / Slack)   |
                      +-------------------+-------------------+
                                          |
                                          v
                      +-------------------+-------------------+
                      |   Temporal Workflow Orchestrator      |
                      +-------------------+-------------------+
                                          |
            +-----------------------------+-----------------------------+
            |                                                           |
            v                                                           v
+-----------+-------------------+                           +-----------+-------------------+
|  V1 Execution Adapters        |                           |  V2 Distributed Agent Mesh    |
| (SSH, WinRM, K8s, AWS SSM)    |                           |  (mTLS + gRPC + Auto-Update)  |
+-------------------------------+                           +-------------------------------+
```

---

## Architectural Components

### 1. Ingestion & Vulnerability Intelligence Core
- **Plugin Architecture**: Abstract interface `BaseScannerPlugin` allows dynamic registration of scanner ingestion adapters.
- **Normalizer**: Translates raw vendor payloads (Qualys XML, Rapid7 JSON, Nessus XML, Trivy JSON) into a unified `VulnerabilityItem` model.
- **Feeds**: Real-time integration with NVD v2.0 API, CISA KEV, and FIRST EPSS.

### 2. Multi-Factor Deterministic Risk Engine
Computes risk deterministically without relying on non-deterministic LLM scoring:
$$\text{RiskScore} = (\text{CVSS} \times 0.30) + (\text{EPSS} \times 0.25) + (\text{KEV\_Multiplier} \times 0.20) + (\text{AssetCriticality} \times 0.15) + (\text{NetworkExposure} \times 0.10)$$

### 3. Cognitive AI Firewall & LLM Planner
- **Strict Bounded Output**: Uses Pydantic v2 schemas (`RemediationPlanSchema`) enforced via API parameters.
- **No Command Execution**: LLM generates action definitions (e.g., package name, method, target version), NEVER shell commands or executable scripts.
- **Sanitizer Guard**: Rejects prompt injection tokens and unvalidated JSON fields.

### 4. Authoritative Policy Engine (OPA)
- Written in Rego (`policies/remediation_rules.rego`).
- Evaluates remediation plans against hard organizational boundaries:
  - Block production patching during business hours.
  - Require senior analyst escalation for kernel and core OS updates.
  - Reject plans with missing rollback definitions.

### 5. Temporal Workflow Orchestrator
- Guarantees durable execution of long-running workflows.
- Handles network blips, step retries, HITL approval timeouts, execution state tracking, and failure compensation.

### 6. Execution Adapters (Multi-OS V1 & V2 Agent)
- **Linux (`apt`, `dnf`, `apk`, `zypper`)**: Idempotent package upgrades via SSH / Paramiko / Ansible Runner.
- **Windows (`WinRM`, `PSWindowsUpdate`, `WSUS`)**: Powershell-templated updates via PyWinRM.
- **Kubernetes**: Zero-downtime container image updates and rolling deployment restarts.
- **Virtual Patching**: Automated ModSecurity WAF rules and kernel hardening parameters (`sysctl`) for zero-day mitigations.
- **V2 Distributed Agent**: Lightweight daemon communicating via gRPC over mTLS with dual-partition A/B auto-upgrades and hardware watchdog recovery.

### 7. Immutable Cryptographic Merkle Audit Trail
- Every state transition emits an immutable `AuditEvent`.
- SHA-256 hash of event $N$ includes hash of event $N-1$ (Merkle chain), preventing silent log manipulation.

### 8. CI/CD & PyPI OIDC Trusted Publishing
- **CI Pipeline** (`.github/workflows/ci.yml`): Runs formatting (`black`, `isort`), linting (`flake8`), pre-commit hooks, and test suite execution (`pytest`) on every commit/PR.
- **PyPI Release Pipeline** (`.github/workflows/publish.yml`): OIDC-trusted publishing (`pypa/gh-action-pypi-publish@release/v1`) triggered on GitHub Release or manual `workflow_dispatch` to package and deploy [`nexora-mythos-fix`](https://pypi.org/project/nexora-mythos-fix/).
