# Workspace Agent Guidelines & Style Rules — Nexora (Mythos Fix)

This repository contains **Nexora (Mythos Fix)**, a governed autonomous vulnerability remediation control plane.

## Engineering Rules & Quality Standards

1. **Deterministic Governance**: AI LLMs must ONLY generate structured JSON plans (`RemediationPlanSchema`). Never execute non-sanitized shell scripts or direct commands from LLMs.
2. **PyPI Packaging Integrity**: Package name is `nexora-mythos-fix`. Ensure `[project.urls]`, `keywords`, and classifiers in `pyproject.toml` remain complete and valid.
3. **Zero Deprecation Warnings**: Maintain strict `-W error::DeprecationWarning` cleanliness across all unit and integration tests.
4. **Merkle Audit Trail**: All state changes must emit SHA-256 hash-chained audit events to maintain non-repudiation.
5. **Quality Gates**: Always run `python -m pytest` and `python -m build` before declaring changes complete.
