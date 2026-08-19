# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Instead, please report security vulnerabilities by emailing **security@nexora.io** (or the project maintainers directly) with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and provide a timeline for assessment and remediation.

## Security Model

Nexora is designed with a **safety-first architecture**:

- **LLMs never execute commands** - AI models function strictly as structured JSON plan generators
- **Cognitive AI Firewall** - Input/output sanitization bounds LLM interactions
- **OPA Policy Gatekeeper** - Formally verified policy enforcement (Rego)
- **Human-in-the-Loop (HITL)** - Mandatory authorization via Web Dashboard or MS Teams/Slack Adaptive Cards
- **Immutable Audit Ledger** - Merkle-tree cryptographic hash chaining (SHA-256)
- **mTLS gRPC** - Mutual TLS for agent communication (Phase 11+)

## Threat Model

Nexora addresses the following threat categories:

1. **Prompt Injection / Plan Poisoning** - Mitigated by Cognitive Firewall + JSON Schema validation
2. **Privilege Escalation** - Mitigated by OPA policy gates + RBAC + approval workflows
3. **Supply Chain Compromise** - Mitigated by signed container images (Cosign) + SBOM verification
4. **Audit Tampering** - Mitigated by Merkle hash-chained ledger
5. **Agent Spoofing** - Mitigated by mTLS + agent registration + heartbeat validation

## Responsible Disclosure

We follow coordinated vulnerability disclosure:

1. You report privately
2. We validate and assess impact
3. We develop and test a fix
4. We release a patch with CVE assignment (if applicable)
5. Public disclosure after users have time to upgrade

## Security-Related Configuration

- **OPA Policies**: Review `policies/*.rego` for environment rules
- **Secrets Management**: Use HashiCorp Vault or AWS Secrets Manager (see `services/execution_engine/secrets_manager.py`)
- **Certificate Rotation**: mTLS certificates auto-rotate; see `services/v2_agent/mtls.py`
- **Audit Retention**: Configure retention in `services/audit/ledger.py`

## Acknowledgments

We thank all security researchers who responsibly disclose vulnerabilities.
