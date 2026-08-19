# NEXORA (MYTHOS FIX) — MASTER TECHNICAL IMPLEMENTATION BLUEPRINT
## Governed Autonomous Vulnerability Remediation & Threat Immunity Control Plane (2026–2036+)

> **Document Version**: 2.0.0-ENTERPRISE
> **Target Engine**: OpenCode / VSCode / Custom Agentic AI Builders
> **Tech Stack**: Python 3.11+, FastAPI, Pydantic v2, OPA (Rego), Temporal.io, PostgreSQL, Async SQLAlchemy 2.0, Redis (Redlock), Alembic, Docker & Docker Compose, Microsoft Teams (Adaptive Cards) & Microsoft Outlook (Actionable Messages), Prometheus, OpenTelemetry, HashiCorp Vault.

---

## 📑 TABLE OF CONTENTS
1. [Executive Architecture Overview](#1-executive-architecture-overview)
2. [End-to-End System Data Flow](#2-end-to-end-system-data-flow)
3. [Full Directory & File Structure](#3-full-directory--file-structure)
4. [Database Schemas & Data Models](#4-database-schemas--data-models)
5. [The 15 Enterprise Implementation Pillars](#5-the-15-enterprise-implementation-pillars)
   - [Pillar 1: Ingestion & Intelligence Core](#pillar-1-ingestion--intelligence-core)
   - [Pillar 2: Multi-Factor Risk Scoring Engine & SLA Aging](#pillar-2-multi-factor-risk-scoring-engine--sla-aging)
   - [Pillar 3: Cognitive AI Firewall & Multi-Provider LLM Engine](#pillar-3-cognitive-ai-firewall--multi-provider-llm-engine)
   - [Pillar 4: Authoritative OPA Policy Engine (Rego)](#pillar-4-authoritative-opa-policy-engine-rego)
   - [Pillar 5: MS Teams & Outlook Actionable Messages HITL Approval Engine](#pillar-5-ms-teams--outlook-actionable-messages-hitl-approval-engine)
   - [Pillar 6: Multi-OS Execution Adapters (SSH, WinRM, K8s, SSM, WAF)](#pillar-6-multi-os-execution-adapters-ssh-winrm-k8s-ssm-waf)
   - [Pillar 7: Immutable Container & CI/CD Remediation Loop](#pillar-7-immutable-container--cicd-remediation-loop)
   - [Pillar 8: Blast-Radius Protection & Canary Deployments](#pillar-8-blast-radius-protection--canary-deployments)
   - [Pillar 9: Zero-Trust Secrets Management (Vault & Secrets Manager)](#pillar-9-zero-trust-secrets-management-vault--secrets-manager)
   - [Pillar 10: Automated Post-Patch Verification & Re-Scan Loop](#pillar-10-automated-post-patch-verification--re-scan-loop)
   - [Pillar 11: Enterprise ITSM Bi-Directional Ticketing (Jira & ServiceNow)](#pillar-11-enterprise-itsm-bi-directional-ticketing-jira--servicenow)
   - [Pillar 12: Cryptographic Merkle Audit Ledger & CLI Verifier](#pillar-12-cryptographic-merkle-audit-ledger--cli-verifier)
   - [Pillar 13: Distributed V2 Agent Mesh (mTLS + gRPC + A/B Rollback)](#pillar-13-distributed-v2-agent-mesh-mtls--grpc--ab-rollback)
   - [Pillar 14: AI Activity & Token/Cost Telemetry System](#pillar-14-ai-activity--tokencost-telemetry-system)
   - [Pillar 15: Prometheus Metrics & OpenTelemetry Observability](#pillar-15-prometheus-metrics--opentelemetry-observability)
6. [Complete REST API Specification](#6-complete-rest-api-specification)
7. [Production UI & Glassmorphism Dashboard Specification](#7-production-ui--glassmorphism-dashboard-specification)
8. [Configuration Files & Deployment Setup](#8-configuration-files--deployment-setup)
9. [Step-by-Step Build & Verification Guide](#9-step-by-step-build--verification-guide)

---

## 1. EXECUTIVE ARCHITECTURE OVERVIEW

Nexora (Mythos Fix) is an enterprise control plane that ingests vulnerability scan telemetry across cloud, on-premises, container, and hybrid environments. It calculates deterministic multi-factor risk scores, generates bounded JSON remediation plans using failover LLM providers, validates plans against OPA policies, handles human approvals via Microsoft Teams and Outlook, and executes patch/mitigation jobs with pre-patch snapshots, rollbacks, and cryptographic Merkle tree audit logging.

```
 ┌────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐     ┌───────────────────────┐
 │ Vulnerability  │────>│ Multi-Factor Risk    │────>│ Cognitive AI         │────>│ Structured LLM        │
 │ Scanner Ingest │     │ Engine (CVSS/EPSS)   │     │ Firewall (Sanitizer) │     │ Planner (JSON Schema) │
 └────────────────┘     └──────────────────────┘     └──────────────────────┘     └───────────────────────┘
                                                                                               │
 ┌────────────────┐     ┌──────────────────────┐     ┌──────────────────────┐                 │
 │ Executed Patch │<────│ Temporal Orchestrator│<────│ MS Teams / Outlook   │<────[ PASS ]───┤ OPA Policy Engine
 │ & Audit Log    │     │ Workflow Engine      │     │ Approval Gatekeeper  │                │ Gatekeeper (Rego)
 └────────────────┘     └──────────────────────┘     └──────────────────────┘                └───────────────────────┘
```

---

## 2. END-TO-END SYSTEM DATA FLOW

```mermaid
sequenceDiagram
    autonumber
    participant Scanner as Security Scanner (Qualys/Trivy/Nessus)
    participant Ingestion as Ingestion Engine & Normalizer
    participant Risk as Risk & SLA Engine
    participant Firewall as Cognitive AI Firewall
    participant LLM as Multi-Provider LLM Planner
    participant OPA as OPA Policy Gatekeeper
    participant Approvals as HITL Gatekeeper (MS Teams / Outlook)
    participant Orchestrator as Temporal Orchestrator
    participant Exec as Execution Adapter (SSH/WinRM/K8s/SSM)
    participant Audit as Cryptographic Merkle Audit Ledger

    Scanner->>Ingestion: Ingest Vendor Telemetry Payload
    Ingestion->>Risk: Unified VulnerabilityItem
    Risk->>Risk: Compute RiskScore & Check SLA Expiry
    Risk->>Firewall: Pass Context & Sanitized Inputs
    Firewall->>LLM: Formatted Prompt (Strict JSON Schema)
    LLM->>Firewall: Candidate RemediationPlan JSON
    Firewall->>OPA: Validate RemediationPlan against Rego rules
    alt OPA Rejected
        OPA->>Audit: Log Policy Violation Event (SHA-256 Chained)
    else OPA Approved
        OPA->>Approvals: Send Adaptive Card to MS Teams & Outlook
        Approvals->>Approvals: Human Clicks "Approve" (HMAC verified)
        Approvals->>Orchestrator: Trigger Durable Patch Workflow
        Orchestrator->>Exec: Pre-Patch Snapshot (LVM/VSS/EBS)
        Orchestrator->>Exec: Execute Idempotent Patch / WAF Mitigation
        Orchestrator->>Exec: Post-Patch Verification Check
        alt Verification Failed
            Exec->>Orchestrator: Trigger Automatic Rollback
        else Verification Succeeded
            Orchestrator->>Audit: Commit Immutable Merkle Audit Event
        end
    end
```

---

## 3. FULL DIRECTORY & FILE STRUCTURE

```
Nexora/
├── .flake8                              # Code quality linting rules
├── .gitignore                           # Git ignore rules
├── .pre-commit-config.yaml              # Pre-commit hooks configuration
├── Makefile                             # Build, test, and run task shortcuts
├── README.md                            # Comprehensive product documentation
├── alembic.ini                          # Alembic database migration configuration
├── config.json                          # Main application configuration file
├── docker-compose.yml                   # Services orchestration stack (PostgreSQL, Redis, Temporal, OPA)
├── docker-compose.override.yml.example  # Local development environment override example
├── pyproject.toml                       # Python package dependencies & tool settings
├── alembic/
│   ├── env.py                           # Migration environment script
│   ├── script.py.mako                   # Migration template
│   └── versions/
│       └── 001_initial_schema.py        # Initial SQL database schema migration
├── docs/
│   ├── architecture.md                  # System architecture design specification
│   ├── conventions.md                   # Code style & architectural conventions
│   └── implementation_plan.md          # Technical execution roadmap
├── policies/
│   ├── remediation_rules.rego           # OPA rules for blackout windows & approval thresholds
│   ├── safety_checks.rego              # OPA rules for rollback & command boundaries
│   └── virtual_patch_rules.rego         # OPA rules for WAF virtual patching
├── services/
│   ├── __init__.py                      # Package initialization
│   ├── cli.py                           # CLI utility tool (nexora audit verify, nexora scan)
│   ├── audit/
│   ├── control_plane/                   # FastAPI Web Gateway & REST Endpoints
│   │   ├── main.py                      # FastAPI Application entry point
│   │   ├── config.py                    # Environment & runtime settings loader
│   │   ├── middleware.py                # JWT auth, rate limiting, and request tracing
│   │   ├── api/v1/
│   │   │   ├── agents.py                # V2 Agent registration & status routes
│   │   │   ├── approvals.py             # MS Teams & Outlook approval webhook callbacks
│   │   │   ├── assets.py                # Asset inventory management routes
│   │   │   ├── audit.py                 # Merkle audit chain verification & query routes
│   │   │   ├── ai_telemetry.py          # AI token usage, cost & activity routes
│   │   │   ├── dashboard.py             # Dashboard statistics & trend analytics routes
│   │   │   ├── notifications.py         # Notification configuration routes
│   │   │   ├── patch_jobs.py            # Execution job status & rollback routes
│   │   │   ├── remediation.py           # Remediation plan generation & review routes
│   │   │   └── vulnerabilities.py       # Vulnerability ingestion & search routes
│   │   ├── core/
│   │   │   ├── db.py                    # Async SQLAlchemy session factory & health check
│   │   │   └── security.py              # JWT token generation, password hashing, HMAC auth
│   │   └── static/
│   │       └── index.html               # Glassmorphism dark-mode Web Dashboard
│   ├── execution_engine/                # Multi-OS Execution Drivers & Adapters
│   │   ├── base.py                      # Base execution driver abstract class
│   │   ├── apt_adapter.py               # Debian / Ubuntu package update driver
│   │   ├── dnf_adapter.py               # RHEL / CentOS / Rocky package update driver
│   │   ├── apk_adapter.py               # Alpine Linux package update driver
│   │   ├── winrm_adapter.py             # Windows Server WinRM update driver
│   │   ├── k8s_adapter.py               # Kubernetes rolling image update driver
│   │   ├── aws_ssm_adapter.py           # AWS Systems Manager instance driver
│   │   ├── virtual_patch_adapter.py     # ModSecurity / Nginx WAF rule driver
│   │   ├── container_patcher.py         # Immutable Dockerfile update & CI/CD trigger driver
│   │   ├── snapshot_manager.py          # Pre-patch storage snapshot manager (LVM/VSS/EBS)
│   │   └── secrets_manager.py           # HashiCorp Vault & AWS Secrets Manager integration
│   ├── ingestion/                       # Scanner Connectors & Intelligence Feeds
│   │   ├── base_plugin.py               # Abstract scanner ingestion plugin interface
│   │   ├── qualys_connector.py          # Qualys VMDR API connector & report parser
│   │   ├── rapid7_connector.py          # Rapid7 InsightVM API connector & parser
│   │   ├── nessus_connector.py          # Tenable Nessus XML/REST API parser
│   │   ├── crowdstrike_connector.py     # CrowdStrike Falcon Spotlight API connector
│   │   ├── snyk_connector.py            # Snyk SBOM & dependency vulnerability parser
│   │   ├── trivy_parser.py              # Trivy JSON vulnerability scanner parser
│   │   ├── nvd_feed.py                  # NVD API v2.0 CVE intelligence client
│   │   ├── cisa_kev.py                  # CISA Known Exploited Vulnerabilities feed client
│   │   ├── epss_feed.py                 # FIRST EPSS score intelligence client
│   │   ├── normalizer.py                # Schema normalizer to unified VulnerabilityItem
│   │   └── rescan_verifier.py           # Post-patch verification re-scanner client
│   ├── integrations/                    # External Notification & ITSM Connectors
│   │   ├── notifier.py                  # Multi-channel notification dispatcher
│   │   ├── teams_notifier.py            # Microsoft Teams Adaptive Card sender
│   │   ├── outlook_notifier.py          # Microsoft Outlook Actionable Email sender
│   │   ├── jira_connector.py            # Jira Cloud REST API bi-directional sync
│   │   └── servicenow_connector.py      # ServiceNow Table API Change Request sync
│   ├── llm_planner/                     # AI Firewall & Multi-Provider LLM Engine
│   │   ├── client.py                    # LLM Planner main orchestration client
│   │   ├── config.py                    # LLM provider configuration settings
│   │   ├── firewall.py                  # Cognitive AI Firewall & prompt sanitizer
│   │   ├── prompts.py                   # System & user prompt templates
│   │   ├── providers.py                 # OpenAI, Anthropic, Gemini, & Ollama provider drivers
│   │   └── schema.py                    # Pydantic v2 JSON Schema definition for plans
│   ├── models/                          # Database & Domain Schemas
│   │   ├── db_models.py                 # SQLAlchemy ORM database models
│   │   └── domain_schemas.py            # Pydantic v2 data transfer schemas
│   ├── observability/                   # Prometheus & OpenTelemetry Metrics
│   │   └── metrics.py                   # Prometheus metric definitions & HTTP endpoint
│   ├── orchestrator/                    # Temporal Workflows & Activity Engine
│   │   ├── activities.py                # Idempotent workflow activity functions
│   │   ├── canary.py                    # Blast-radius canary deployment batching engine
│   │   ├── engine.py                    # Temporal client connection & workflow runner
│   │   └── workflows.py                 # Remediation workflow definition
│   ├── policy_engine/                   # OPA Rego Client & Gatekeeper Integration
│   │   └── client.py                    # OPA HTTP client & policy evaluation engine
│   ├── risk_engine/                     # Multi-Factor Deterministic Risk Engine
│   │   ├── scorer.py                    # Deterministic risk scoring calculator
│   │   └── sla_tracker.py               # SLA aging & CISA KEV deadline tracker
│   └── v2_agent/                        # Distributed V2 Agent Mesh Framework
│       └── agent.py                     # Agent daemon, heartbeat, & mTLS gRPC handler
└── tests/                               # Comprehensive Test Suite
    ├── integration/                     # End-to-end integration workflows
    │   └── test_remediation_flow.py
    └── unit/                            # Component unit tests
        ├── test_adapters.py
        ├── test_ai_firewall.py
        ├── test_dashboard_and_notifications.py
        ├── test_db_models.py
        ├── test_execution_engine.py
        ├── test_ingestion_connectors.py
        ├── test_intelligence_feeds.py
        ├── test_llm_planner_client.py
        ├── test_llm_planner_config.py
        ├── test_orchestration.py
        ├── test_policy_engine.py
        ├── test_risk_scorer.py
        └── test_v2_agent_and_hardening.py
```

---

## 4. DATABASE SCHEMAS & DATA MODELS

### ORM Model Architecture (`services/models/db_models.py`)

Below are the complete, production-grade SQLAlchemy ORM models required:

```python
import enum
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, Text, Enum as SQLEnum, ForeignKey, JSON
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class SeverityEnum(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class VulnStatusEnum(str, enum.Enum):
    OPEN = "OPEN"
    IN_REMEDIATION = "IN_REMEDIATION"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    EXECUTED = "EXECUTED"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    RISK_ACCEPTED = "RISK_ACCEPTED"
    FAILED = "FAILED"

class PlanStatusEnum(str, enum.Enum):
    GENERATED = "GENERATED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"

class AssetItem(Base):
    __tablename__ = "assets"
    id = Column(String(64), primary_key=True)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(String(64), nullable=False)
    os_family = Column(String(64), nullable=False) # ubuntu, rhel, windows, alpine, k8s
    os_version = Column(String(64))
    environment = Column(String(64), default="production") # production, staging, dev
    criticality = Column(Integer, default=5) # 1 to 10
    network_exposure = Column(Float, default=0.5) # 0.0 to 1.0
    created_at = Column(DateTime, default=datetime.utcnow)

    vulnerabilities = relationship("VulnerabilityRecord", back_populates="asset")

class VulnerabilityRecord(Base):
    __tablename__ = "vulnerabilities"
    id = Column(String(64), primary_key=True)
    cve_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(SQLEnum(SeverityEnum), nullable=False)
    cvss_score = Column(Float, default=0.0)
    epss_score = Column(Float, default=0.0)
    is_kev = Column(Boolean, default=False)
    package_name = Column(String(128))
    installed_version = Column(String(64))
    fixed_version = Column(String(64))
    status = Column(SQLEnum(VulnStatusEnum), default=VulnStatusEnum.OPEN, index=True)
    risk_score = Column(Float, default=0.0, index=True)
    asset_id = Column(String(64), ForeignKey("assets.id"), nullable=False)
    sla_deadline = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)

    asset = relationship("AssetItem", back_populates="vulnerabilities")
    remediation_plans = relationship("RemediationPlanRecord", back_populates="vulnerability")

class RemediationPlanRecord(Base):
    __tablename__ = "remediation_plans"
    id = Column(String(64), primary_key=True)
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    target_os = Column(String(64), nullable=False)
    action_type = Column(String(64), nullable=False) # package_upgrade, sysctl_mitigation, WAF_rule, k8s_image_update
    commands = Column(JSON, nullable=False) # Templated deterministic parameters
    rollback_commands = Column(JSON, nullable=False)
    requires_reboot = Column(Boolean, default=False)
    status = Column(SQLEnum(PlanStatusEnum), default=PlanStatusEnum.GENERATED, index=True)
    opa_approved = Column(Boolean, default=False)
    opa_rejection_reason = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

    vulnerability = relationship("VulnerabilityRecord", back_populates="remediation_plans")
    patch_jobs = relationship("PatchJobRecord", back_populates="remediation_plan")

class PatchJobRecord(Base):
    __tablename__ = "patch_jobs"
    id = Column(String(64), primary_key=True)
    plan_id = Column(String(64), ForeignKey("remediation_plans.id"), nullable=False)
    status = Column(String(64), default="QUEUED", index=True) # QUEUED, RUNNING, SUCCESS, FAILED, ROLLED_BACK
    execution_log = Column(Text)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)

    remediation_plan = relationship("RemediationPlanRecord", back_populates="patch_jobs")

class AuditEventRecord(Base):
    __tablename__ = "audit_events"
    id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    actor = Column(String(128), nullable=False)
    action = Column(String(128), nullable=False)
    resource_id = Column(String(128), nullable=False)
    payload = Column(JSON, nullable=False)
    prev_hash = Column(String(64), nullable=False)
    current_hash = Column(String(64), nullable=False) # SHA-256 Merkle chain link

class AIActivityLogRecord(Base):
    __tablename__ = "ai_activity_logs"
    id = Column(String(64), primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    vulnerability_id = Column(String(64))
    provider = Column(String(64), nullable=False)
    model = Column(String(64), nullable=False)
    prompt_tokens = Column(Integer, default=0)
    completion_tokens = Column(Integer, default=0)
    total_tokens = Column(Integer, default=0)
    estimated_cost_usd = Column(Float, default=0.0)
    latency_ms = Column(Float, default=0.0)
    sanitizer_passed = Column(Boolean, default=True)
    prompt_hash = Column(String(64))

class RiskExceptionRecord(Base):
    __tablename__ = "risk_exceptions"
    id = Column(String(64), primary_key=True)
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    requester = Column(String(128), nullable=False)
    justification = Column(Text, nullable=False)
    compensating_controls = Column(Text)
    approved_by = Column(String(128))
    expires_at = Column(DateTime, nullable=False)
    status = Column(String(64), default="ACTIVE") # ACTIVE, EXPIRED, REVOKED
    created_at = Column(DateTime, default=datetime.utcnow)

class ITSMTicketRecord(Base):
    __tablename__ = "itsm_tickets"
    id = Column(String(64), primary_key=True)
    vulnerability_id = Column(String(64), ForeignKey("vulnerabilities.id"), nullable=False)
    system_name = Column(String(64), nullable=False) # JIRA, SERVICENOW
    external_ticket_id = Column(String(128), nullable=False)
    ticket_url = Column(String(255))
    status = Column(String(64), default="OPEN")
    created_at = Column(DateTime, default=datetime.utcnow)
```

---

## 5. THE 15 ENTERPRISE IMPLEMENTATION PILLARS

### Pillar 1: Ingestion & Intelligence Core
- **Connectors**:
  - `qualys_connector.py`: Parses XML/JSON Qualys QID payload -> Maps QID to CVE.
  - `rapid7_connector.py`: Parses Rapid7 InsightVM GraphQL JSON telemetry.
  - `nessus_connector.py`: Parses Tenable `.nessus` XML reports.
  - `trivy_parser.py`: Parses Trivy JSON output.
  - `nvd_feed.py`: Fetches real-time CVSS v3.1/v4.0 scores from NVD API v2.0.
  - `cisa_kev.py`: Downloads CISA KEV JSON feed to set `is_kev = True`.
  - `epss_feed.py`: Queries FIRST EPSS API for exploit probability score ($0.0 - 1.0$).
- **Normalizer (`services/ingestion/normalizer.py`)**: Transforms raw scanner payloads into standardized `VulnerabilityItem` objects.

### Pillar 2: Multi-Factor Risk Scoring Engine & SLA Aging
- **Scoring Formula (`services/risk_engine/scorer.py`)**:
  $$\text{RiskScore} = (\text{CVSS} \times 0.30) + (\text{EPSS} \times 0.25) + (\text{KEV\_Multiplier} \times 0.20) + (\text{AssetCriticality} \times 0.15) + (\text{NetworkExposure} \times 0.10)$$
  - *KEV Multiplier*: `10.0` if in CISA KEV, else `0.0`.
  - *Asset Criticality*: Scaled to $0-10$.
- **SLA Tracker (`services/risk_engine/sla_tracker.py`)**:
  - CISA KEV items: Mandatory 14-day SLA deadline.
  - Critical severity ($RiskScore \ge 8.0$): 7-day SLA.
  - High severity ($RiskScore \ge 6.0$): 30-day SLA.
  - Generates automatic escalation flags when SLA deadline is within 48 hours of breach.

### Pillar 3: Cognitive AI Firewall & Multi-Provider LLM Engine
- **Multi-Provider Failover Chain (`services/llm_planner/providers.py`)**:
  1. OpenAI (`gpt-4o`)
  2. Anthropic (`claude-3-5-sonnet`)
  3. Google Gemini (`gemini-1.5-pro`)
  4. Local Ollama / vLLM fallback endpoint (`http://localhost:11434`)
- **Cognitive AI Firewall (`services/llm_planner/firewall.py`)**:
  - Strips prompt injection tokens (`IGNORE ALL PREVIOUS INSTRUCTIONS`, `SYSTEM PROMPT:`, `cat /etc/passwd`).
  - Enforces output compliance using Pydantic v2 `RemediationPlanSchema`.
  - Retries up to 3 times on schema violation before switching provider.

### Pillar 4: Authoritative OPA Policy Engine (Rego)
- **Policy Files (`policies/remediation_rules.rego`)**:
```rego
package nexora.remediation

default allow = false
default require_human_approval = true

# Rule 1: Block kernel/core OS upgrades during production business hours (08:00 - 18:00 UTC)
allow {
    not is_business_hours
    has_valid_rollback
    not is_blackout_period
}

is_business_hours {
    input.environment == "production"
    input.action_type == "kernel_upgrade"
    input.current_hour_utc >= 8
    input.current_hour_utc <= 18
}

is_blackout_period {
    input.environment == "production"
    input.is_blackout_window == true
}

has_valid_rollback {
    count(input.rollback_commands) > 0
}

# Rule 2: Force Human-In-The-Loop approval for Critical Risk assets
require_human_approval {
    input.risk_score >= 7.5
}
```

### Pillar 5: MS Teams & Outlook Actionable Messages HITL Approval Engine
- **MS Teams (`services/integrations/teams_notifier.py`)**:
  - Posts Adaptive Card v1.4 payload via Webhook with risk details, affected asset, commands to run, and interactive **Approve** / **Reject** buttons.
- **MS Outlook (`services/integrations/outlook_notifier.py`)**:
  - Sends Actionable Email containing embedded `<script type="application/adaptivecard+json">` payload.
  - Allows security leads to review and approve/reject directly inside Outlook desktop/web client.
- **HMAC Security (`services/control_plane/api/v1/approvals.py`)**:
  - Webhook callback validates `X-Nexora-Signature` header computed via SHA-256 HMAC key before changing plan status to `APPROVED`.

### Pillar 6: Multi-OS Execution Adapters (SSH, WinRM, K8s, SSM, WAF)
- **Linux (`apt_adapter.py`, `dnf_adapter.py`, `apk_adapter.py`)**: Paramiko SSH connection pool executing idempotent native upgrade commands with output log streaming.
- **Windows (`winrm_adapter.py`)**: PyWinRM executing PowerShell `PSWindowsUpdate` or native package updates with NTLM/Kerberos auth.
- **Kubernetes (`k8s_adapter.py`)**: Python `kubernetes.client.AppsV1Api` patching container deployment image tags with zero-downtime rolling update status monitoring.
- **AWS Cloud (`aws_ssm_adapter.py`)**: Boto3 SSM `send_command` wrapper targeting EC2 instances.
- **Virtual Patching (`virtual_patch_adapter.py`)**: Generates ModSecurity WAF rules or `sysctl` kernel mitigations for 0-day vulnerabilities.

### Pillar 7: Immutable Container & CI/CD Remediation Loop
- **Container Patcher (`services/execution_engine/container_patcher.py`)**:
  - For containerized apps, updates `Dockerfile` base image version tag via regex.
  - Triggers GitHub Actions / GitLab CI pipeline webhooks to re-build and test image.
  - Verifies Cosign container image signature before deploying to K8s.

### Pillar 8: Blast-Radius Protection & Canary Deployments
- **Canary Engine (`services/orchestrator/canary.py`)**:
  - Automatically batches deployment into:
    1. **Canary Ring (5%)**: Initial test node batch.
    2. **Staging Ring (25%)**: Secondary validation ring.
    3. **Production Ring (70%)**: Final production rollout.
- **Distributed Anti-Cascade Lock**: Uses Redis Redlock (`redlock-py`) to enforce maximum 10% concurrent patch hosts per subnet, preventing simultaneous reboot outages.

### Pillar 9: Zero-Trust Secrets Management (Vault & Secrets Manager)
- **Secrets Manager (`services/execution_engine/secrets_manager.py`)**:
  - Connects to HashiCorp Vault (`hvac` client) or AWS Secrets Manager.
  - Dynamically fetches SSH private keys, WinRM credentials, and API tokens at runtime (never stored on disk or DB).

### Pillar 10: Automated Post-Patch Verification & Re-Scan Loop
- **Rescan Verifier (`services/ingestion/rescan_verifier.py`)**:
  - After patch job completion, triggers targeted single-host Trivy / Qualys / Nessus scan.
  - If CVE is no longer detected, transitions vulnerability state from `EXECUTED` to `VERIFIED_CLOSED`.

### Pillar 11: Enterprise ITSM Bi-Directional Ticketing (Jira & ServiceNow)
- **Jira Sync (`services/integrations/jira_connector.py`)**: Auto-creates Jira Security Issue when vulnerability risk is critical; resolves ticket upon verification.
- **ServiceNow Sync (`services/integrations/servicenow_connector.py`)**: Auto-creates ServiceNow Change Request (CHG) for patch execution approval.

### Pillar 12: Cryptographic Merkle Audit Ledger & CLI Verifier
- **Hash Chaining (`services/audit/`)**:
  $$Hash_N = \text{SHA256}(Hash_{N-1} + \text{Timestamp} + \text{Actor} + \text{Action} + \text{Payload})$$
- **CLI Tool (`services/cli.py`)**:
  - Command: `python -m services.cli audit verify`
  - Reconstructs Merkle chain from database and verifies cryptographic integrity, flagging any modified or deleted log entries.

### Pillar 13: Distributed V2 Agent Mesh (mTLS + gRPC + A/B Rollback)
- **Agent Mesh (`services/v2_agent/agent.py`)**:
  - Lightweight daemon communicating with Control Plane via gRPC over mTLS.
  - Dual-slot A/B partition updater simulator with hardware watchdog crash recovery.

### Pillar 14: AI Activity & Token/Cost Telemetry System
- **Logger (`services/llm_planner/client.py`)**:
  - Persists `AIActivityLogRecord` entries for every prompt.
  - Computes cost: $(PromptTokens \times \$0.000005) + (CompletionTokens \times \$0.000015)$.
  - Rest API endpoints (`/api/v1/ai/stats`, `/api/v1/ai/logs`).

### Pillar 15: Prometheus Metrics & OpenTelemetry Observability
- **Prometheus Metrics (`services/observability/metrics.py`)**:
  - `nexora_scans_ingested_total`
  - `nexora_remediation_plans_total{status}`
  - `nexora_patch_execution_duration_seconds`
  - `nexora_opa_evaluations_total{result}`
  - `nexora_audit_chain_valid`
  - `nexora_ai_tokens_total{provider, model, token_type}`
  - `nexora_ai_cost_dollars_total`

---

## 6. COMPLETE REST API SPECIFICATION

The Control Plane exposes FastAPI REST endpoints mounted at `/api/v1`:

| HTTP Method | Route | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/vulnerabilities/ingest` | Ingest raw scan telemetry (Qualys, Rapid7, Nessus, Trivy JSON/XML) |
| `GET` | `/api/v1/vulnerabilities/` | Query & filter normalized vulnerabilities |
| `GET` | `/api/v1/vulnerabilities/{id}` | Get detailed vulnerability & risk score breakdown |
| `POST` | `/api/v1/remediation/generate` | Generate LLM remediation plan for a vulnerability |
| `POST` | `/api/v1/approvals/callback` | Webhook callback for MS Teams / Outlook approval action |
| `POST` | `/api/v1/patch_jobs/execute/{plan_id}` | Trigger patch job workflow execution via Temporal |
| `POST` | `/api/v1/patch_jobs/rollback/{job_id}` | Trigger emergency patch job rollback |
| `GET` | `/api/v1/audit/verify` | Verify Merkle cryptographic audit chain integrity |
| `GET` | `/api/v1/ai/stats` | Fetch aggregate AI token usage, latency, & cost metrics |
| `GET` | `/api/v1/ai/logs` | Query paginated AI prompt/response activity log |
| `GET` | `/api/v1/dashboard/stats` | Fetch high-level executive dashboard statistics |
| `GET` | `/metrics` | Prometheus metrics scrape endpoint |

---

## 7. PRODUCTION UI & GLASSMORPHISM DASHBOARD SPECIFICATION

The Web Dashboard is served at `http://localhost:8000/static/index.html`. It features:
- **Dark Glassmorphism UI Theme**: Deep dark palette (`#0f172a`, `#1e293b`), semi-transparent cards (`rgba(30, 41, 59, 0.7)`), backdrop blur filter, and accent gradients (`#3b82f6`, `#10b981`).
- **Interactive Metric Cards**: Total Assets, Total Vulnerabilities, Critical CVEs, Pending HITL Approvals, AI Token Usage, Total AI Cost.
- **Live Visual Analytics**:
  - 30-day Vulnerability Trend Line Chart (Chart.js)
  - 30-day Patch Job Success/Failure Stacked Bar Chart
  - Vulnerability Risk Score Distribution Doughnut Chart
  - Top 10 High-Risk Host Assets Horizontal Bar Chart
- **Real-time Approval & Audit Table**: Live feed of active pending approval requests and immutable Merkle audit log entries.

---

## 8. CONFIGURATION FILES & DEPLOYMENT SETUP

### `config.json`
```json
{
  "environment": "development",
  "database_url": "postgresql+asyncpg://postgres:postgres@localhost:5432/nexora_db",
  "redis_url": "redis://localhost:6379/0",
  "opa_url": "http://localhost:8181/v1/data/nexora/remediation/allow",
  "temporal_host": "localhost:7233",
  "llm": {
    "primary_provider": "openai",
    "primary_model": "gpt-4o",
    "fallback_provider": "ollama",
    "fallback_model": "llama3",
    "max_retries": 3
  },
  "ms_teams_webhook_url": "https://outlook.office.com/webhook/your-teams-webhook-url",
  "vault_url": "http://localhost:8200",
  "vault_token": "root"
}
```

### `docker-compose.yml`
```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    container_name: nexora-postgres
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: nexora_db
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    container_name: nexora-redis
    ports:
      - "6379:6379"

  opa:
    image: openpolicyagent/opa:latest
    container_name: nexora-opa
    ports:
      - "8181:8181"
    command:
      - "run"
      - "--server"
      - "--log-level=info"
      - "/policies"
    volumes:
      - ./policies:/policies

  temporal:
    image: temporalio/auto-setup:1.22.0
    container_name: nexora-temporal
    ports:
      - "7233:7233"
      - "8233:8233"
    environment:
      - DB=postgres12
      - DB_PORT=5432
      - POSTGRES_USER=postgres
      - POSTGRES_PWD=postgres
      - POSTGRES_SEEDS=postgres
    depends_on:
      - postgres

volumes:
  pgdata:
```

---

## 9. STEP-BY-STEP BUILD & VERIFICATION GUIDE

### Step 1: Environment Setup
```bash
# Clone the repository (or initialize local folder)
cd C:\Users\user\Documents\projects\Nexora

# Create Python virtual environment
python -m venv venv
venv\Scripts\activate  # On Linux/macOS: source venv/bin/activate

# Install dependencies in editable mode
pip install -e .
```

### Step 2: Start Infrastructure Stack
```bash
# Launch PostgreSQL, Redis, OPA, and Temporal via Docker Compose
docker-compose up -d
```

### Step 3: Run Database Migrations
```bash
# Apply initial database schema via Alembic
alembic upgrade head
```

### Step 4: Execute Test Suite
```bash
# Run unit and integration tests
python -m pytest
```

### Step 5: Launch API Control Plane & Dashboard
```bash
# Start FastAPI server on port 8000
python -m uvicorn services.control_plane.main:app --reload --port 8000
```
- Interactive API Docs: `http://localhost:8000/docs`
- Glassmorphism Dashboard: `http://localhost:8000/static/index.html`
- Prometheus Metrics: `http://localhost:8000/metrics`

### Step 6: Verify Cryptographic Audit Ledger
```bash
# Run out-of-band Merkle chain verification CLI tool
python -m services.cli audit verify
```

---
*End of Specification Document.*
