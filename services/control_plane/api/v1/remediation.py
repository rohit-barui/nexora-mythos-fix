from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from services.control_plane.core.db import get_db
from services.llm_planner.client import LLMPlannerClient
from services.models.db_models import Asset, RemediationPlan, Vulnerability
from services.models.domain_schemas import RemediationPlanCreate, RemediationPlanResponse
from services.observability.metrics import record_opa_evaluation, record_remediation_plan
from services.policy_engine.client import OPAPolicyClient

router = APIRouter(prefix="/remediation", tags=["Remediation Plans"])
llm_client = LLMPlannerClient()
opa_client = OPAPolicyClient()


@router.post("/generate", response_model=RemediationPlanResponse)
async def generate_plan(payload: RemediationPlanCreate, db: AsyncSession = Depends(get_db)):
    asset = await db.get(Asset, payload.asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    vuln_records = []
    for v_id in payload.vulnerability_ids:
        v = await db.get(Vulnerability, v_id)
        if v:
            vuln_records.append(
                {
                    "cve_id": v.cve_id,
                    "package_name": v.package_name,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "risk_score": v.calculated_risk_score,
                }
            )

    # 1. Generate bounded plan via LLM & Cognitive AI Firewall (records AI telemetry)
    plan_schema = await llm_client.generate_remediation_plan(
        asset_info={
            "hostname": asset.hostname,
            "os_type": asset.os_type,
            "environment": asset.environment,
            "criticality_score": asset.criticality_score,
        },
        vulnerabilities=vuln_records,
        db=db,
        vulnerability_id=str(payload.vulnerability_ids[0]) if payload.vulnerability_ids else None,
    )

    # 2. Evaluate plan with OPA Policy Engine
    opa_res = await opa_client.evaluate_plan(
        asset_info={
            "hostname": asset.hostname,
            "os_type": asset.os_type,
            "environment": asset.environment,
            "criticality_score": asset.criticality_score,
        },
        plan_payload=plan_schema.model_dump(),
    )

    record_opa_evaluation("allowed" if opa_res.get("allowed") else "denied")

    status = "PENDING_APPROVAL" if opa_res.get("allowed") else "REJECTED_BY_POLICY"
    record_remediation_plan(status)

    plan = RemediationPlan(
        asset_id=asset.asset_id,
        vulnerability_ids=[str(v_id) for v_id in payload.vulnerability_ids],
        generated_by_llm=True,
        planner_model="gpt-4o-mini",
        plan_payload=plan_schema.model_dump(),
        opa_evaluation_result=opa_res,
        status=status,
    )
    db.add(plan)
    await db.commit()
    await db.refresh(plan)
    return plan


@router.get("/plans", response_model=List[RemediationPlanResponse])
async def list_plans(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(RemediationPlan))
    return result.scalars().all()
