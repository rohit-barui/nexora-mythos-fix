import os
import time
from contextlib import asynccontextmanager

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_client import Counter, Gauge, Histogram, generate_latest
from starlette.responses import Response

# Prometheus metrics
REQUEST_COUNT = Counter(
    "nexora_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_LATENCY = Histogram(
    "nexora_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "endpoint"],
)

PATCH_JOBS_TOTAL = Counter(
    "nexora_patch_jobs_total",
    "Total patch jobs executed",
    ["status"],
)

VULNERABILITIES_INGESTED = Counter(
    "nexora_vulnerabilities_ingested_total",
    "Total vulnerabilities ingested",
    ["scanner"],
)

SCANS_INGESTED_TOTAL = Counter(
    "nexora_scans_ingested_total",
    "Total vulnerability scans ingested",
    ["scanner"],
)

REMEDIATION_PLANS_TOTAL = Counter(
    "nexora_remediation_plans_total",
    "Total remediation plans generated",
    ["status"],
)

PATCH_EXECUTION_DURATION = Histogram(
    "nexora_patch_execution_duration_seconds",
    "Patch execution duration in seconds",
    ["execution_type"],
)

OPA_EVALUATIONS_TOTAL = Counter(
    "nexora_opa_evaluations_total",
    "Total OPA policy evaluations",
    ["result"],
)

AUDIT_CHAIN_VALID = Gauge(
    "nexora_audit_chain_valid",
    "Audit Merkle chain validity (1 valid, 0 tampered)",
)

AI_TOKENS_TOTAL = Counter(
    "nexora_ai_tokens_total",
    "Total AI tokens consumed",
    ["provider", "model", "token_type"],
)

AI_COST_DOLLARS_TOTAL = Counter(
    "nexora_ai_cost_dollars_total",
    "Total estimated AI cost in USD",
)


def setup_telemetry(service_name: str = "nexora-control-plane") -> None:
    """Initialize OpenTelemetry tracing."""
    resource = Resource.create({"service.name": service_name})
    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")
    try:
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
    except Exception:
        # OTLP not available, use console exporter for dev
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter

        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))

    trace.set_tracer_provider(provider)


def instrument_app(app) -> None:
    """Auto-instrument FastAPI, HTTPX, and SQLAlchemy."""
    FastAPIInstrumentor.instrument_app(app)
    HTTPXClientInstrumentor().instrument()
    SQLAlchemyInstrumentor().instrument(enable_commenter=True, commenter_options={})


@asynccontextmanager
async def metrics_middleware(request, call_next):
    """Middleware to record Prometheus metrics."""
    start = time.time()
    method = request.method
    path = request.url.path

    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        status = 500
        raise
    finally:
        duration = time.time() - start
        REQUEST_COUNT.labels(method=method, endpoint=path, status=status).inc()
        REQUEST_LATENCY.labels(method=method, endpoint=path).observe(duration)

    return response


def get_metrics() -> Response:
    """Expose Prometheus metrics endpoint."""
    return Response(content=generate_latest(), media_type="text/plain")


def record_patch_job(status: str) -> None:
    """Record patch job execution metric."""
    PATCH_JOBS_TOTAL.labels(status=status).inc()


def record_vulnerability_ingested(scanner: str) -> None:
    """Record vulnerability ingestion metric."""
    VULNERABILITIES_INGESTED.labels(scanner=scanner).inc()


def record_scan_ingested(scanner: str) -> None:
    """Record scan ingestion metric (blueprint Pillar 15)."""
    SCANS_INGESTED_TOTAL.labels(scanner=scanner).inc()


def record_remediation_plan(status: str) -> None:
    """Record remediation plan generation metric."""
    REMEDIATION_PLANS_TOTAL.labels(status=status).inc()


def record_patch_execution_duration(execution_type: str, duration_seconds: float) -> None:
    """Record patch execution duration histogram."""
    PATCH_EXECUTION_DURATION.labels(execution_type=execution_type).observe(duration_seconds)


def record_opa_evaluation(result: str) -> None:
    """Record OPA policy evaluation metric (result: allowed|denied|error)."""
    OPA_EVALUATIONS_TOTAL.labels(result=result).inc()


def set_audit_chain_valid(valid: bool) -> None:
    """Set audit Merkle chain validity gauge (1 valid, 0 tampered)."""
    AUDIT_CHAIN_VALID.set(1 if valid else 0)


def record_ai_tokens(provider: str, model: str, token_type: str, count: int) -> None:
    """Record AI token consumption metric (token_type: prompt|completion)."""
    AI_TOKENS_TOTAL.labels(provider=provider, model=model, token_type=token_type).inc(count)


def record_ai_cost(cost_usd: float) -> None:
    """Record estimated AI cost in USD."""
    AI_COST_DOLLARS_TOTAL.inc(cost_usd)
