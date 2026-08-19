# Comprehensive Platform Architecture & Execution Roadmap: Mythos Fix (Nexora)

## Executive Summary
**Mythos Fix / Nexora** is an enterprise-grade, **governed autonomous vulnerability remediation control plane**. It is designed to remediate security vulnerabilities across cloud, container, on-premises, and hybrid infrastructure.

### Core Product Philosophy & 10+ Year Threat Immunity
This product is built to be deployed **immediately**, while its architecture is engineered to remain **immune to next-decade security threats (2026–2036+)**, including super-intelligent AI models (Mythos-class threat actors, autonomous exploit engines, AI agent swarms, and zero-day synthesis engines).

- **Deterministic Governance Over AI**: AI (LLMs) is used ONLY for structured plan suggestion, NEVER for direct command execution or approval.
- **Cognitive AI Firewall & Anti-Jailbreak Engine**: Bounded Pydantic v2 schemas and zero-trust sanitization eliminate prompt injection, plan poisoning, and Trojan patch injections.
- **Formally Verified Policy Gate (OPA)**: Hard mathematical boundaries that super-intelligent models cannot bypass.
- **Cryptographic Merkle Audit Trail**: Immutable logging with SHA-256 hash chaining to detect any state tampering.

---

## Scanner Integration Ecosystem & Ingestion Engine

Mythos Fix includes a pluggable **Ingestion Core** supporting both file-based scans and direct API integrations with leading enterprise security vendors:

1. **Enterprise Vulnerability Scanners**:
   - **Qualys Guard / VMDR**: Qualys API v2 XML/JSON payload parser & QID vulnerability mapper.
   - **Rapid7 InsightVM / Nexpose**: GraphQL API connector & Nexpose XML report parsing.
   - **Tenable Nessus / Tenable.io**: REST API export connector & `.nessus` file parser.
   - **CrowdStrike Falcon Spotlight**: Streaming API connector for real-time endpoint vulnerability telemetry.
   - **Microsoft Defender for Cloud**: Azure Resource Graph & Security Center API integration.
   - **Snyk & Dependency-Track**: Software Bill of Materials (SBOM) and open-source supply chain risk ingestion.

2. **Open Scanner & Intelligence Feeds**:
   - **Trivy / Grype**: Container image and filesystem JSON report parsers.
   - **NVD API v2.0**: Live CVE data, CVSS v3.1/v4.0 scoring, and CPE 2.3 matching.
   - **CISA KEV (Known Exploited Vulnerabilities)**: Real-time active exploit flag matching.
   - **FIRST EPSS (Exploit Prediction Scoring System)**: Predictive exploit probability metrics.

---

## Technical Deep-Dive: Multi-OS Patching, Application Controls & Sandboxing

### 1. Multi-OS Execution Drivers & Safety Lifecycle

| Environment / OS | Execution Protocol | Native Package / Patch Mechanism | Rollback Mechanism | Pre-Patch Snapshot |
| :--- | :--- | :--- | :--- | :--- |
| **Debian / Ubuntu** | SSH / Paramiko / Ansible | `apt-get install --only-upgrade <pkg>` | `apt-get install <pkg>=<prev_ver>` | LVM Snapshot / ZFS |
| **RHEL / CentOS / Rocky** | SSH / Paramiko / Ansible | `dnf update -y <pkg>` | `dnf history undo <id>` | LVM Snapshot |
| **Alpine Linux** | SSH / Paramiko / Ansible | `apk add --upgrade <pkg>` | `apk add <pkg>=<prev_ver>` | Disk Snapshot |
| **SUSE / SLES** | SSH / Paramiko / Ansible | `zypper update -y <pkg>` | Snapper Btrfs Revert | Btrfs Snapper |
| **Windows Server** | WinRM / PyWinRM | `PSWindowsUpdate`, `WSUS`, `winget` | System Restore / VSS | Volume Shadow Copy (VSS) |
| **Kubernetes Clusters** | K8s API / Helm | Image Tag Update, `kubectl set image` | `helm rollback`, `kubectl rollout undo` | Ephemeral Pod Dry-run |
| **Cloud Instances** | AWS SSM / GCP OS | SSM Document Execution | EBS / Persistent Disk Swap | AWS EBS / GCP Disk Snapshot |

### 2. Ephemeral Sandbox Patch Verification & Application Controls
- **Sandbox Pre-Execution Dry-Run**: For high-criticality assets, patch plans are first executed in an ephemeral container/VM clone (using Firecracker or Docker) to test application stability before touching production.
- **Virtual Patching Workarounds**: Automatic deployment of WAF rules (ModSecurity, AWS WAF, Cloudflare) and sysctl/kernel mitigations when official vendor patches do not yet exist for zero-day vulnerabilities.
- **Zero-Downtime Application Controls**: Traffic redirection via HAProxy/ALB targets, graceful process reloads (`systemctl reload`), and Kubernetes zero-downtime rolling restarts.

---

## Repository Structure (Current)

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
│   ├── remediation_rules.rego
│   ├── safety_checks.rego
│   └── virtual_patch_rules.rego
├── services/
│   ├── control_plane/                  # FastAPI Gateway & API Routes
│   ├── models/                         # DB Models & Pydantic v2 Schemas
│   ├── ingestion/                      # Qualys, Rapid7, Nessus, Trivy, NVD Plugins
│   ├── risk_engine/                    # Deterministic Risk Scoring Module
│   ├── llm_planner/                    # Cognitive AI Firewall & LLM Engine
│   ├── policy_engine/                  # OPA Policy Gatekeeper Integration
│   ├── orchestrator/                   # Temporal Workflows & Activities
│   ├── execution_engine/               # Multi-OS Execution Adapters
│   │   ├── apt_adapter.py
│   │   ├── dnf_adapter.py
│   │   ├── apk_adapter.py
│   │   ├── winrm_adapter.py
│   │   ├── k8s_adapter.py
│   │   ├── aws_ssm_adapter.py          # AWS SSM Run Command (Phase 10)
│   │   ├── container_patcher.py        # Dockerfile/compose tag rewrite (Phase 10)
│   │   ├── virtual_patch_adapter.py
│   │   ├── snapshot_manager.py
│   │   ├── secrets_manager.py          # Vault + AWS Secrets Manager (Phase 10)
│   │   ├── ab_rollback.py              # A/B dual-slot rollback (Phase 11)
│   │   └── registry.py
│   ├── orchestrator/
│   │   ├── canary.py                   # Canary deployment + Redlock (Phase 10)
│   │   └── engine.py
│   ├── ingestion/
│   │   └── rescan_verifier.py          # Post-patch rescan (Phase 10)
│   ├── audit/
│   │   └── ledger.py                   # Merkle hash-chained audit
│   ├── observability/
│   │   ├── metrics.py
│   │   └── audit.py
│   └── v2_agent/                       # Distributed Agent Framework (V2)
│       ├── agent.py                    # HTTP + optional gRPC
│       ├── mtls.py                     # Self-signed CA + identity certs
│       ├── grpc_server.py              # mTLS gRPC server
│       ├── grpc_client.py              # Async gRPC client
│       ├── proto/agent.proto           # Protobuf definitions
│       └── agent_pb2*.py               # Generated gRPC code
├── tests/                              # 190 tests, 84.6% coverage
└── cli.py                              # nexora CLI (Phase 12)
```

---

## Implementation Phases — **ALL COMPLETE**

### Phase 1–7: Foundations (Ingestion, Risk, Planning, Orchestration, API, Agents, Hardening)
- Scanner ingestion plugins (Qualys, Rapid7, Nessus, Trivy, NVD, CISA KEV, EPSS)
- Deterministic risk scoring (CVSS/EPSS/KEV/Asset/Exposure weights)
- Cognitive AI Firewall + structured LLM planner (OpenAI/Anthropic/Gemini/Ollama)
- OPA policy gatekeeper with Rego policies
- Temporal workflows + activities + in-process fallback
- Multi-OS execution adapters (apt, dnf, apk, winrm, k8s, virtual_patch, sysctl)
- Snapshot manager (LVM, EBS, VSS)
- FastAPI control plane with audit ledger

### Phase 8: Data & Telemetry Core
- **SLA Tracker**: KEV 14d / critical 7d / high 30d / standard 90d + 48h escalation
- **AI Activity Log**: Full telemetry of LLM prompts, responses, costs
- **Risk Exceptions**: Structured exception workflow with approval chain
- **ITSMTicket**: Unified Jira/ServiceNow tracking table
- **JWT + HMAC**: PyJWT authentication, HMAC-SHA256 for webhook verification
- **Metrics**: Prometheus counters/histograms for scans, patches, OPA, AI activity

### Phase 9: HITL Approvals & ITSM
- **MS Teams Adaptive Card v1.4**: Interactive Approve/Reject buttons with HMAC-signed payloads
- **MS Outlook Actionable Messages**: Embedded adaptive cards via base64 script
- **HMAC-Verified Callback**: `POST /approvals/callback` with X-Nexora-Signature
- **Jira Cloud Connector**: Issue creation, resolution, status sync + ITSMTicket persistence
- **ServiceNow Connector**: Change Request CRUD + ITSMTicket persistence
- **Emergency Rollback**: `POST /patch-jobs/{id}/rollback` with audit logging

### Phase 10: Execution & Ops
- **AWS SSM Adapter**: Run Command execution with hermetic local fallback
- **Container Patcher**: Dockerfile/compose tag rewrite + Cosign digest verification
- **Canary Orchestrator**: 5% → 25% → 70% → 100% rings + Redlock anti-cascade (in-process fallback)
- **Secrets Manager**: Vault / AWS Secrets Manager / in-process backends
- **Rescan Verifier**: Post-patch rescan with retry loop for verification
- **CLI**: `nexora audit verify`, `nexora scan report`, `nexora scan rescan-verify`

### Phase 11: V2 Agent gRPC/mTLS + A/B Rollback
- **gRPC AgentService**: Register, Heartbeat, Execute, GetStatus (protobuf)
- **Mutual TLS**: Self-signed CA + CA-signed identity certs, server requires client auth
- **Async gRPC Client**: Control plane → agent communication
- **V2Agent Optional gRPC Mode**: Backward-compatible HTTP path retained
- **A/B Dual-Slot Manager**: Promote/confirm/rollback between deployment slots

---

## Verification Plan

### Automated Tests
- **Scanner Ingestion**: Qualys XML, Rapid7 JSON, Trivy output parsing
- **AI Firewall & Schema Security**: Pydantic validation blocks malformed LLM payloads
- **Multi-OS Adapter Dry-Runs**: apt, dnf, winrm, k8s, virtual_patch, sysctl, ssm, docker_image
- **OPA Policy Unit Testing**: Business hours, kernel escalation, mandatory approvals
- **Canary + Redlock**: Ring progression, contention blocking, anti-cascade
- **HITL Callbacks**: HMAC signature valid/invalid, Teams/Outlook card structure
- **A/B Rollback**: Slot promotion, confirmation, rollback state transitions
- **Rescan Verifier**: Verification pass/fail with retry semantics

### Coverage & Quality Gates
- **190 tests passing**
- **84.6% coverage** (gate: >= 50%)
- **Zero deprecation warnings** (`-W error::DeprecationWarning`)
- **Lint clean**: black, isort, flake8 (max-line-length=100)

### Manual Verification
```bash
# Start stack
docker-compose up -d

# Run migrations
alembic upgrade head

# Start API
uvicorn services.control_plane.main:app --reload

# Verify API docs
open http://localhost:8000/docs
```

---

## Deployment Notes

### Required Infrastructure
- **PostgreSQL 15+** (asyncpg)
- **Redis 7+** (for Redlock + caching)
- **Temporal Server** (optional - in-process fallback available)
- **OPA Server** (optional - embedded client available)

### Environment Variables
See `config.json` and `services/control_plane/config.py` for full configuration options.

### Security Hardening
- Rotate `SECRET_KEY` in production (min 32 bytes)
- Replace self-signed mTLS certs with PKI-issued certificates
- Configure Vault/AWS Secrets Manager for production secrets
- Enable audit log retention policies

---

## License
Apache License 2.0 — see [LICENSE](../LICENSE)
