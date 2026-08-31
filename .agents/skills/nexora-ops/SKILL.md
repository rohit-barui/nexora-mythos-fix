---
name: nexora-ops
description: Operational cheatsheet for building, testing, verifying, and publishing the Nexora (Mythos Fix) security control plane.
---

# Nexora Operational Skill

This skill provides workflow instructions for developing, testing, auditing, and publishing the **Nexora (Mythos Fix)** autonomous vulnerability remediation control plane.

## Key Architecture & Components

- **Control Plane**: FastAPI Web Gateway (`services/control_plane/`)
- **Risk Scoring**: Multi-factor engine (`services/risk_engine/`)
- **AI Intelligence**: Cognitive AI Firewall + LLM Planner (`services/llm_planner/`)
- **Policy Gatekeeper**: OPA Rego rules (`policies/` & `services/policy_engine/`)
- **Execution Drivers**: Multi-OS adapters (`services/execution_engine/`)
- **Agent Mesh**: V2 gRPC + mTLS mesh (`services/v2_agent/`)
- **Audit Ledger**: Merkle hash-chained ledger (`services/audit/`)

## Essential Commands

### 1. Build & Test
```bash
# Run complete test suite
python -m pytest tests/ --cov=services --cov-report=term-missing

# Lint & Format checks
black --check services tests
isort --check services tests
flake8 services tests
```

### 2. Package & Validate PyPI Release
```bash
# Build sdist & wheel
python -m build

# Validate metadata
python -m twine check dist/*
```

### 3. Deploy Stack Locally
```bash
# Infrastructure
docker-compose up -d

# Migrations
alembic upgrade head

# FastAPI Server
python -m uvicorn services.control_plane.main:app --reload
```
