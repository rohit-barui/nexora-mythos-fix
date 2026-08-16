# Nexora Engineering Conventions (HARD RULES)

The following rules are non-negotiable and apply to ALL development activity in this
repository, regardless of task size or urgency.

---

## 1. Git Branch Workflow (MANDATORY)

1. Create a new branch for **every** new task taken up.
2. Complete all tasks and updates in the new branch.
3. Once everything is completed, **take the user's confirmation for completion**.
4. Only after the user approves: **push all updates to GitHub**, then **merge the new branch to main**.
5. After merge, take the latest updates and **delete the branch**.
6. All activities must be completed **end-to-end with no gaps, misses, or skips**.
   Nothing is done to a minimum. Everything must be tested and verified **before** step 4.

## 2. LINT & TEST ENFORCEMENT (MANDATORY — NO FAILURES ALLOWED)

Lint and CI/CD failures must **never** reach the repository. Enforcement is automatic:

- **Pre-commit hooks** (`.pre-commit-config.yaml`) run automatically before every commit:
  - `black` (formatting, line-length 100)
  - `isort` (import sorting, black profile)
  - `flake8` (lint, max-line-length 100)
  - `end-of-file-fixer`, `trailing-whitespace`, YAML/JSON validation
  - `pytest` (full test suite)
- **CI pipeline** (`.github/workflows/ci.yml`) runs on every push to `main` and every
  pull request against `main`:
  - `pip install -e .[dev]`
  - `black --check services tests`
  - `isort --check services tests`
  - `flake8 services tests`
  - `pytest tests/ --cov=services --cov-report=term-missing --cov-fail-under=50`
  - app import smoke check
- **`make ci`** runs the exact same checks locally (matches the CI pipeline).

### Rules

- **Never** commit code that fails `black`, `isort`, `flake8`, or `pytest`.
- **Never** merge a branch whose CI is red.
- Before completing ANY task: run `make ci` (or the equivalent commands) and ensure it
  passes 100% with zero warnings treated as failures.
- When contributing new code, run `black` and `isort` (or `make lint-fix`) first, then
  verify with `flake8` and `pytest`.
- Fix lint/test issues in the **same branch/commit** where they are introduced —
  do not defer cleanup.

## 3. Verification Before Completion

Every task, no matter how small, must be verified end-to-end before being marked done:

- All tests pass.
- Lint, formatting, and import-sorting are clean.
- The application imports cleanly.
- The changed behaviour is exercised by a test where feasible.
