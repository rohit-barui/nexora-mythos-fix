# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-31

### Added
- **Phase 11: V2 Agent gRPC/mTLS + A/B Rollback** (`a97acc7`)
  - Protobuf schema (`proto/agent.proto`) with AgentService: Register, Heartbeat, Execute, GetStatus
  - Self-signed CA + CA-signed identity certificates (`mtls.py`)
  - Async gRPC server/client (`grpc_server.py`, `grpc_client.py`)
  - V2Agent optional gRPC mode with backward-compatible HTTP path
  - A/B dual-slot deployment manager (`ab_rollback.py`) with promote/confirm/rollback
  - 15 new tests

- **Phase 10: Execution & Ops** (`d19fc6d`)
  - AWS SSM Run Command adapter with hermetic in-process fallback (`aws_ssm_adapter.py`)
  - Container image patcher: Dockerfile/compose tag rewrite + Cosign digest verification (`container_patcher.py`)
  - Canary orchestrator: 5% → 25% → 70% → 100% rings + Redlock anti-cascade (`canary.py`)
  - Secrets manager: HashiCorp Vault / AWS Secrets Manager / in-process backends (`secrets_manager.py`)
  - Post-patch rescan verifier with retry loop (`rescan_verifier.py`)
  - CLI tool: `nexora audit verify`, `nexora scan report`, `nexora scan rescan-verify` (`cli.py`)
  - Wired canary + Redlock into `POST /patch-jobs/{id}/execute`
  - 42 new tests

- **Phase 9: HITL Approvals & ITSM** (`d957d1e`)
  - MS Teams Adaptive Card v1.4 notifier with HMAC-signed Approve/Reject buttons (`teams_notifier.py`)
  - MS Outlook Actionable Messages with embedded adaptive card JSON (`outlook_notifier.py`)
  - HMAC-verified approval callback: `POST /approvals/callback` with `X-Nexora-Signature` (`approvals.py`)
  - Jira Cloud connector: issue create/get/update + `ITSMTicket` persistence (`jira_connector.py`)
  - ServiceNow connector: Change Request CRUD + `ITSMTicket` persistence (`servicenow_connector.py`)
  - Emergency rollback endpoint: `POST /patch-jobs/{id}/rollback` (`patch_jobs.py`)
  - 12 new tests

- **Phase 8: Data & Telemetry Core** (`755fb64`)
  - SLA tracker with tiered deadlines: KEV 14d, Critical 7d, High 30d, Standard 90d + 48h escalation (`sla_tracker.py`)
  - AI Activity Log model for full LLM telemetry (prompts, responses, costs) (`models.py`)
  - Risk Exception workflow with approval chain (`models.py`)
  - `ITSMTicket` unified tracking model (`models.py`)
  - JWT authentication (PyJWT) + HMAC-SHA256 webhook verification (`security.py`)
  - Multi-provider LLM planner with fallback (OpenAI, Anthropic, Gemini, Ollama) (`llm_planner/`)
  - AI telemetry REST API endpoints
  - 7 new Prometheus metrics (scans, patches, OPA, AI activity, canary, etc.)
  - Alembic migration for new tables
  - 26 new tests

- **Phases 1–7: Foundations** (initial development)
  - Scanner ingestion plugins: Qualys, Rapid7, Nessus, Trivy, NVD, CISA KEV, EPSS
  - Deterministic risk scoring (CVSS/EPSS/KEV/Asset/Exposure weighted formula)
  - Cognitive AI Firewall + structured LLM planner with Pydantic v2 schemas
  - OPA policy gatekeeper with Rego policies (remediation, safety, virtual patching)
  - Temporal workflows/activities with in-process fallback
  - Multi-OS execution adapters: apt, dnf, apk, winrm, k8s, virtual_patch, sysctl
  - Snapshot manager: LVM, EBS, VSS
  - FastAPI control plane with API routes (assets, vulnerabilities, remediation, approvals, audit)
  - Merkle hash-chained immutable audit ledger
  - 110 tests, 85.2% coverage

### Documentation
- `LICENSE` — Apache-2.0
- `CONTRIBUTING.md` — Development setup, coding standards, PR guidelines
- `SECURITY.md` — Vulnerability reporting, threat model, responsible disclosure
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `README.md` — Updated with accurate repo structure, quick start, CLI usage, project status
- `docs/implementation_plan.md` — Complete rewrite reflecting all 11 phases

### Quality Gates
- **190 tests passing**
- **84.6% code coverage** (gate: ≥50%)
- **Zero deprecation warnings** (`-W error::DeprecationWarning`)
- **Lint clean**: black, isort, flake8 (max-line-length=100)

---

## [Unreleased]

### Planned
- Phase 12: Production hardening (observability, scaling, disaster recovery)
- Phase 13: Advanced AI features (root cause analysis, predictive remediation)
- Phase 14: Compliance automation (CIS, NIST, SOC2 report generation)
- Phase 15: Multi-tenant SaaS mode with RBAC namespaces
