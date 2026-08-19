import uuid
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.core.db import get_db
from services.ingestion.normalizer import IngestionNormalizer
from services.models.db_models import Asset, Vulnerability
from services.models.domain_schemas import VulnerabilityResponse
from services.observability.metrics import record_scan_ingested, record_vulnerability_ingested
from services.risk_engine.scorer import RiskScorer
from services.risk_engine.sla_tracker import compute_sla_deadline

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])
normalizer = IngestionNormalizer()


@router.post("/ingest/{asset_id}", response_model=List[VulnerabilityResponse])
async def ingest_scan_payload(
    asset_id: uuid.UUID,
    scanner_type: str = Query("trivy", description="qualys, rapid7, nessus, trivy"),
    raw_payload: Dict[str, Any] = ...,
    db: AsyncSession = Depends(get_db),
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    items = await normalizer.normalize_scan(scanner_type, raw_payload)
    created_vulns = []

    for item in items:
        risk_score = RiskScorer.calculate_risk_score(
            cvss_score=item.cvss_score,
            epss_score=item.epss_score,
            is_known_exploited=item.is_known_exploited,
            asset_criticality=asset.criticality_score,
            exposure_level=asset.exposure_level,
        )

        vuln = Vulnerability(
            asset_id=asset.asset_id,
            cve_id=item.cve_id,
            package_name=item.package_name,
            installed_version=item.installed_version,
            fixed_version=item.fixed_version,
            cvss_score=item.cvss_score,
            epss_score=item.epss_score,
            is_known_exploited=item.is_known_exploited,
            calculated_risk_score=risk_score,
            scanner_source=scanner_type,
            raw_metadata=item.raw_metadata,
            status="OPEN",
            sla_deadline=compute_sla_deadline(risk_score, item.is_known_exploited),
        )
        db.add(vuln)
        created_vulns.append(vuln)
        record_vulnerability_ingested(scanner_type)

    await db.commit()
    for v in created_vulns:
        await db.refresh(v)

    record_scan_ingested(scanner_type)
    return created_vulns


@router.get("", response_model=List[VulnerabilityResponse])
async def list_vulnerabilities(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Vulnerability))
    return result.scalars().all()
