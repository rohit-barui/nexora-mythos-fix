from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from services.control_plane.api.v1.approvals import router as approvals_router
from services.control_plane.api.v1.assets import router as assets_router
from services.control_plane.api.v1.audit import router as audit_router
from services.control_plane.api.v1.dashboard import router as dashboard_router
from services.control_plane.api.v1.notifications import router as notifications_router
from services.control_plane.api.v1.patch_jobs import router as patch_jobs_router
from services.control_plane.api.v1.remediation import router as remediation_router
from services.control_plane.api.v1.vulnerabilities import router as vulns_router
from services.control_plane.config import settings
from services.control_plane.core.db import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize SQLite / PostgreSQL tables if in dev mode
    try:
        await init_db()
    except Exception:
        pass
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Governed Autonomous Vulnerability Remediation Control Plane API",
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Set CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "HEALTHY", "service": settings.PROJECT_NAME, "version": settings.VERSION}


# Mount Routers under API_V1_STR
app.include_router(assets_router, prefix=settings.API_V1_STR)
app.include_router(vulns_router, prefix=settings.API_V1_STR)
app.include_router(remediation_router, prefix=settings.API_V1_STR)
app.include_router(approvals_router, prefix=settings.API_V1_STR)
app.include_router(audit_router, prefix=settings.API_V1_STR)
app.include_router(dashboard_router, prefix=settings.API_V1_STR)
app.include_router(notifications_router, prefix=settings.API_V1_STR)
app.include_router(patch_jobs_router, prefix=settings.API_V1_STR)

# Static dashboard
app.mount("/static", StaticFiles(directory="services/control_plane/static"), name="static")


@app.get("/dashboard", include_in_schema=False)
async def dashboard_ui():
    return FileResponse("services/control_plane/static/index.html")
