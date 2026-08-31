# Nexora (Mythos Fix) — Governed Autonomous Vulnerability Remediation Platform

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![PyPI](https://img.shields.io/pypi/v/nexora-mythos-fix.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)
![Security](https://img.shields.io/badge/governance-OPA%20%2B%20HITL-orange.svg)
![Orchestration](https://img.shields.io/badge/orchestration-Temporal.io-purple.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)

**Nexora (Mythos Fix)** is an enterprise-grade, **governed autonomous vulnerability remediation control plane** engineered to remediate security vulnerabilities across heterogeneous cloud, container, on-premises, and hybrid infrastructure. Published on PyPI as [`nexora-mythos-fix`](https://pypi.org/project/nexora-mythos-fix/).

---

## 🛡️ Core Philosophy & 10+ Year Threat Immunity

Nexora is designed to be **deployed immediately** while maintaining an architecture built for **next-decade security threat immunity (2026–2036+)**, including super-intelligent AI models (Mythos-class threat actors, autonomous exploit engines, AI agent swarms, and synthetic zero-day exploit generators).

```
 ┌────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
 │ Vulnerability  │────>│ Multi-Factor Risk    │────>│ Cognitive AI         │────>│ Structured LLM        │
 │ Scanner Ingest │     │ Engine (CVSS/EPSS)   │     │ Firewall (Sanitizer) │     │ Planner (JSON Schema) │
 └────────────────┘     └──────────────────────┘     └──────────────────────┘     └───────────────────────┘
                                                                                               │
 ┌────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐                 │
 │ Executed Patch │<────│ Temporal Orchestrator│<────│ HITL Multi-Channel   │<────[ PASS ]───┤ OPA Policy Engine
 │ & Audit Log    │     │ Workflow Engine      │     │ Approval Gatekeeper  │                │ Gatekeeper (Rego)
 └────────────────┘     └──────────────────────┘     └──────────────────────┘                └───────────────────────┘
```

### Key Pillars:
1. **Safety-First Architecture**:
   - **LLMs Never Execute Commands**: AI models function strictly as structured JSON plan generators. Commands are templated, idempotent, and executed by deterministic adapters.
   - **Cognitive AI Firewall**: Input/output sanitization bounds LLM interactions, preventing prompt injection, plan poisoning, and Trojan patch targets.
   - **Formally Verified Policy Gate (OPA)**: Open Policy Agent enforces non-bypassable environment rules, blackout windows, and escalation policies.
   - **Human-in-the-Loop (HITL)**: Mandatory authorization via Web Dashboard or MS Teams/Slack Adaptive Cards.
2. **Immutable Audit Ledger**:
   - Merkle-tree cryptographic hash chaining (SHA-256) ensures state integrity from ingestion -> decision -> approval -> execution -> verification.
3. **Pluggable & Auto-Upgradeable Adapter Architecture**:
   - Micro-kernel plugin structure allows adding new operating systems, scanners, or policy rules without altering control plane core workflows.

---

## 🔌 Scanner Ecosystem & Ingestion Plugins

Nexora provides out-of-the-box ingestion connectors for enterprise security solutions and open vulnerability feeds:

- **Enterprise Scanners**: Qualys VMDR, Rapid7 InsightVM, Tenable Nessus / Tenable.io, CrowdStrike Falcon Spotlight, Microsoft Defender for Cloud, Snyk.
- **Open Tools & Feeds**: Trivy, Grype, NVD API v2.0, CISA KEV (Known Exploited Vulnerabilities), FIRST EPSS (Exploit Prediction Scoring System), OSV.dev, SBOMs (SPDX 2.3 / CycloneDX 1.5).

### Deterministic Risk Scoring Formula:
$$\text{RiskScore} = (\text{CVSS} \times 0.30) + (\text{EPSS} \times 0.25) + (\text{KEV\_Multiplier} \times 0.20) + (\text{AssetCriticality} \times 0.15) + (\text{NetworkExposure} \times 0.10)$$

---

## ⚙️ Multi-OS Patch Execution Matrix

| Environment / OS | Execution Driver | Native Patch Mechanism | Pre-Patch Snapshot | Rollback Strategy |
| :--- | :--- | :--- | :--- | :--- |
| **Debian / Ubuntu** | SSH / Paramiko / Ansible | `apt-get install --only-upgrade <pkg>` | LVM Snapshot / ZFS | `apt-get install <pkg>=<prev_ver>` |
| **RHEL / CentOS / Rocky** | SSH / Paramiko / Ansible | `dnf update -y <pkg>` | LVM Snapshot | `dnf history undo <id>` |
| **Alpine Linux** | SSH / Paramiko / Ansible | `apk add --upgrade <pkg>` | Storage Snapshot | `apk add <pkg>=<prev_ver>` |
| **SUSE / SLES** | SSH / Paramiko / Ansible | `zypper update -y <pkg>` | Btrfs Snapper | Snapper Btrfs Revert |
| **Windows Server** | WinRM / PyWinRM | `PSWindowsUpdate`, `WSUS`, `winget` | VSS Snapshot | System Restore / VSS Revert |
| **Kubernetes** | K8s API / Helm | Image Tag Update / `kubectl set image` | Ephemeral Sandbox | `helm rollback` / `kubectl rollout undo` |
| **Cloud (AWS/GCP)** | AWS SSM / GCP OS | SSM Document Execution | AWS EBS / GCP Disk | EBS / Persistent Disk Swap |

---

## 📁 Repository Structure

```
Nexora/
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── SECURITY.md
├── CODE_OF_CONDUCT.md
├── docker-compose.yml
├── docker-compose.override.yml.example
├── Makefile
├── config.json
├── pyproject.toml
├── alembic.ini
├── docs/
│   ├── architecture.md
│   ├── conventions.md
│   └── implementation_plan.md
├── policies/                            # OPA Rego Policy Suite
├── services/
│   ├── control_plane/                  # FastAPI Gateway & API Routes
│   ├── models/                         # DB Models & Pydantic v2 Schemas
│   ├── ingestion/                      # Qualys, Rapid7, Nessus, Trivy, NVD Plugins
│   ├── risk_engine/                    # Deterministic Risk Scoring Module
│   ├── llm_planner/                    # Cognitive AI Firewall & LLM Engine
│   ├── policy_engine/                  # OPA Policy Gatekeeper Integration
│   ├── orchestrator/                   # Temporal Workflows & Activities
│   ├── execution_engine/               # Multi-OS Execution Adapters
│   └── v2_agent/                       # Distributed Agent Framework (V2)
└── tests/                              # Unit, Integration & Policy Tests
```

---

## 🚀 Quick Start & Installation

### Option A: Install from PyPI (Recommended)
```bash
pip install nexora-mythos-fix
```

### Option B: Local Setup & Source Build
```bash
# Clone the repository
git clone https://github.com/rohit-barui/Nexora.git
cd Nexora

# Create Python Virtual Environment & Install Dependencies
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Launch local stack (PostgreSQL, Redis, Temporal, OPA)
docker-compose up -d

# Run database migrations
alembic upgrade head

# Run API Control Plane Server
uvicorn services.control_plane.main:app --reload
```

The API will be available at `http://localhost:8000` with auto-generated OpenAPI docs at `/docs`.

---

## 🧪 Testing

```bash
# Run full test suite with strict warnings and coverage
pytest tests/ -W error::DeprecationWarning --cov=services --cov-fail-under=50

# Run with verbose output
pytest tests/ -v

# Run specific test file
pytest tests/unit/test_phase10_execution_ops.py -v
```

---

## 📦 CLI Tool

After installation, the `nexora` CLI is available:

```bash
# Verify audit ledger integrity
nexora audit verify

# Generate scan report
nexora scan report --asset "server-01" --items-json '[{"cve_id": "CVE-2026-0001"}]'

# Verify remediation via rescan
nexora scan rescan-verify --asset "server-01" --before-json '[{"cve_id": "CVE-2026-0001"}]' --after-json '[]' --target-cves '["CVE-2026-0001"]'
```

---

## 🔒 Security

See [SECURITY.md](SECURITY.md) for our security policy, threat model, and responsible disclosure process.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding standards, and PR guidelines.

---

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

## 📋 Project Status

All 11 phases of the master blueprint are implemented and tested:

| Phase | Scope | Status |
|-------|-------|--------|
| 1–7 | Foundations (ingestion, risk, planning, orchestration, API, agents, hardening) | ✅ Complete |
| 8 | Data & Telemetry Core (SLA, AI activity logs, JWT/HMAC, LLM planner, metrics) | ✅ Complete |
| 9 | HITL Approvals & ITSM (Teams/Outlook cards, Jira, ServiceNow, rollback) | ✅ Complete |
| 10 | Execution & Ops (SSM, containers, canary+Redlock, secrets, rescan, CLI) | ✅ Complete |
| 11 | V2 Agent gRPC/mTLS + A/B dual-slot rollback | ✅ Complete |

**Verification**: 190 tests passing (100%), 85% coverage, zero deprecation warnings, lint clean.
