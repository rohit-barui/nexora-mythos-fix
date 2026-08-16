.PHONY: help install dev-up dev-down test lint lint-fix ci install-precommit run-api db-migrate

help:
	@echo "Nexora Management Commands:"
	@echo "  make install          Install Python dependencies"
	@echo "  make install-precommit Install pre-commit hooks"
	@echo "  make dev-up           Start Docker containers (PostgreSQL, Redis, OPA, Temporal)"
	@echo "  make dev-down         Stop Docker containers"
	@echo "  make test             Run pytest suite"
	@echo "  make lint             Run code formatters and linter checks"
	@echo "  make lint-fix         Auto-fix formatting and import ordering"
	@echo "  make ci               Run full lint + test + coverage (matches CI pipeline)"
	@echo "  make run-api          Run FastAPI server locally"
	@echo "  make db-migrate       Apply Alembic database migrations"

install:
	pip install -e .[dev]

install-precommit:
	pip install pre-commit
	pre-commit install

dev-up:
	docker-compose up -d

dev-down:
	docker-compose down

test:
	pytest tests/ -v

lint:
	black --check services tests
	isort --check services tests
	flake8 services tests

lint-fix:
	black services tests
	isort services tests

ci:
	black --check services tests
	isort --check services tests
	flake8 services tests
	pytest tests/ --cov=services --cov-report=term-missing --cov-fail-under=50

run-api:
	uvicorn services.control_plane.main:app --reload --host 0.0.0.0 --port 8000

db-migrate:
	alembic upgrade head
