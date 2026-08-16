import uuid
from datetime import datetime
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, ConfigDict

# --- Asset Schemas ---
class AssetBase(BaseModel):
    hostname: str = Field(..., json_schema_extra={"example": "web-prod-01.us-east-1.internal"})
    ip_address: Optional[str] = Field(None, json_schema_extra={"example": "10.0.1.45"})
    os_type: Literal["debian", "rhel", "windows", "alpine", "k8s", "aws_ssm"] = Field("debian")
    environment: Literal["production", "staging", "development"] = Field("production")
    criticality_score: int = Field(5, ge=1, le=10, description="Asset business criticality 1-10")
    exposure_level: Literal["internet-facing", "internal", "isolated"] = Field("internal")

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    asset_id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Vulnerability Schemas ---
class VulnerabilityItem(BaseModel):
    cve_id: str = Field(..., json_schema_extra={"example": "CVE-2024-3094"})
    package_name: str = Field(..., json_schema_extra={"example": "xz-utils"})
    installed_version: str = Field(..., json_schema_extra={"example": "5.6.0-1"})
    fixed_version: Optional[str] = Field(None, json_schema_extra={"example": "5.6.1-1"})
    cvss_score: float = Field(0.0, ge=0.0, le=10.0)
    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    is_known_exploited: bool = Field(False, description="CISA KEV vulnerability flag")
    scanner_source: str = Field("trivy", json_schema_extra={"example": "qualys"})
    raw_metadata: Dict[str, Any] = Field(default_factory=dict)

class VulnerabilityResponse(VulnerabilityItem):
    vulnerability_id: uuid.UUID
    asset_id: uuid.UUID
    calculated_risk_score: float
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Remediation Plan Action Schemas (LLM Output Enforcer) ---
class ActionDefinition(BaseModel):
    action_type: Literal["patch", "virtual_patch", "service_reload", "kernel_hardening", "rollback"] = Field(...)
    target_package: str = Field(..., json_schema_extra={"example": "openssl"})
    method: Literal["apt", "dnf", "apk", "winrm", "k8s_image", "waf_rule", "sysctl"] = Field(...)
    target_version: Optional[str] = Field(None, json_schema_extra={"example": "3.0.2-0ubuntu1.15"})
    restart_required: bool = Field(False)
    rollback_command_template: Optional[str] = Field(None, json_schema_extra={"example": "apt-get install openssl=3.0.2-0ubuntu1.14"})
    pre_patch_checks: List[str] = Field(default_factory=lambda: ["check_disk_space", "verify_snapshot"])

class RemediationPlanSchema(BaseModel):
    actions: List[ActionDefinition] = Field(..., min_length=1)
    estimated_risk_after_patch: Literal["low", "medium", "high"] = Field("low")
    explanation: str = Field(..., description="LLM justification for proposed remediation plan")

class RemediationPlanCreate(BaseModel):
    asset_id: uuid.UUID
    vulnerability_ids: List[uuid.UUID]

class RemediationPlanResponse(BaseModel):
    plan_id: uuid.UUID
    asset_id: uuid.UUID
    vulnerability_ids: List[str]
    generated_by_llm: bool
    planner_model: str
    plan_payload: Dict[str, Any]
    opa_evaluation_result: Dict[str, Any]
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Approval Schemas ---
class ApprovalCreate(BaseModel):
    plan_id: uuid.UUID
    approver: str = Field(..., json_schema_extra={"example": "analyst@company.com"})
    decision: Literal["APPROVED", "REJECTED", "MODIFIED"] = Field("APPROVED")
    comments: Optional[str] = Field(None)
    channel: Literal["WEB_DASHBOARD", "TEAMS_BOT", "SLACK"] = Field("WEB_DASHBOARD")

class ApprovalResponse(ApprovalCreate):
    approval_id: uuid.UUID
    decided_at: datetime

    model_config = ConfigDict(from_attributes=True)

# --- Audit Log Schemas ---
class AuditEventResponse(BaseModel):
    event_id: uuid.UUID
    actor: str
    action: str
    payload: Dict[str, Any]
    previous_event_hash: Optional[str]
    event_hash: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
