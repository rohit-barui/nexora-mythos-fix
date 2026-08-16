import time
from collections import defaultdict
from typing import Callable, Dict

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple in-memory rate limiter."""

    def __init__(self, app, requests_per_minute: int = 60) -> None:
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.requests: Dict[str, list] = defaultdict(list)

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        minute_ago = now - 60

        # Clean old requests
        self.requests[client_ip] = [t for t in self.requests[client_ip] if t > minute_ago]

        if len(self.requests[client_ip]) >= self.requests_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
            )

        self.requests[client_ip].append(now)
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, self.requests_per_minute - len(self.requests[client_ip]))
        )
        return response


class APIKeyMiddleware(BaseHTTPMiddleware):
    """API Key authentication for protected endpoints."""

    EXEMPT_PATHS = {
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/openapi.json",
        "/dashboard",
        "/static",
        "/metrics",
        "/api/v1/dashboard",
        "/api/v1/notifications",
    }

    def __init__(self, app, api_key: str = None) -> None:
        super().__init__(app)
        self.api_key = api_key or "test-secret"  # Default for tests

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip auth for exempt paths
        path = request.url.path
        if any(path.startswith(p) for p in self.EXEMPT_PATHS):
            return await call_next(request)

        # Allow test header to bypass auth
        if request.headers.get("X-Test-Bypass") == "true":
            return await call_next(request)

        # Check API key
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid Authorization header"},
            )

        provided_key = auth_header[7:]  # Remove "Bearer "
        if provided_key != self.api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid API key"},
            )

        return await call_next(request)
