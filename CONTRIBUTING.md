# Contributing to Nexora

Thank you for your interest in contributing to Nexora! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Issues

- Search existing issues first to avoid duplicates
- Use the issue templates when available
- Provide clear reproduction steps, expected vs actual behavior
- Include environment details (OS, Python version, dependencies)

### Submitting Pull Requests

1. Fork the repository and create a feature branch from `main`
2. Ensure your code follows the project's conventions:
   - Run `make lint` or `python -m black/isort/flake8` locally
   - All tests must pass: `pytest tests/ -W error::DeprecationWarning --cov=services --cov-fail-under=50`
3. Write clear commit messages following conventional commits format
4. Update documentation if your changes affect user-facing behavior
5. Submit a PR with a clear description of changes and motivation

### Development Setup

```bash
# Clone your fork
git clone https://github.com/rohit-barui/nexora-mythos-fix.git
cd nexora-mythos-fix

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Start local dependencies (PostgreSQL, Redis, Temporal, OPA)
docker-compose up -d

# Run tests
pytest tests/
```

### Coding Standards

- **Python**: 3.11+
- **Formatting**: Black (line-length=100)
- **Imports**: isort (black profile)
- **Linting**: flake8 (max-line-length=100, ignore E203/W503)
- **Type hints**: Required for new public APIs
- **Tests**: pytest with asyncio, coverage >= 50%

### Architecture Guidelines

- **Safety-first**: LLMs never execute commands directly
- **Deterministic adapters**: All execution paths must be idempotent and verifiable
- **Audit by default**: Every state change logs to the immutable audit ledger
- **Plugin architecture**: New scanners, executors, policies via registry patterns

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Linting passes (`make lint` or equivalent)
- [ ] Coverage maintained (>= 50%)
- [ ] Documentation updated
- [ ] No breaking changes without version bump discussion
- [ ] Security considerations addressed

## Security Issues

Please report security vulnerabilities privately via [SECURITY.md](SECURITY.md) process. Do not open public issues for security flaws.

## Questions?

Open a discussion or reach out to the maintainers.
