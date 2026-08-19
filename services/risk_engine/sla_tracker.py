"""
SLA Aging Tracker (Blueprint Pillar 2).

Computes deterministic remediation SLA deadlines based on vulnerability risk
severity and CISA KEV status, and generates automatic escalation flags when a
deadline approaches within the configured escalation window.

SLA Tiers:
    - CISA KEV            -> mandatory 14-day deadline
    - Critical (>= 8.0)   -> 7-day deadline
    - High    (>= 6.0)   -> 30-day deadline
    - Standard            -> 90-day deadline

Escalation: flagged when the remaining time until the deadline breaches the
48-hour escalation window. All timestamps are naive UTC (consistent with the
platform ORM convention).
"""

from datetime import UTC, datetime, timedelta
from typing import Dict, Optional

KEV_SLA_DAYS = 14
CRITICAL_SLA_DAYS = 7
HIGH_SLA_DAYS = 30
STANDARD_SLA_DAYS = 90
ESCALATION_WINDOW_HOURS = 48

CRITICAL_RISK_THRESHOLD = 8.0
HIGH_RISK_THRESHOLD = 6.0

STATUS_ON_TRACK = "ON_TRACK"
STATUS_AT_RISK = "AT_RISK"
STATUS_ESCALATED = "ESCALATED"
STATUS_BREACHED = "BREACHED"

TIER_KEV = "KEV"
TIER_CRITICAL = "CRITICAL"
TIER_HIGH = "HIGH"
TIER_STANDARD = "STANDARD"


def sla_days_for(risk_score: float, is_kev: bool) -> int:
    """Return the SLA tier deadline (days) for the given risk profile."""
    if is_kev:
        return KEV_SLA_DAYS
    if risk_score >= CRITICAL_RISK_THRESHOLD:
        return CRITICAL_SLA_DAYS
    if risk_score >= HIGH_RISK_THRESHOLD:
        return HIGH_SLA_DAYS
    return STANDARD_SLA_DAYS


def sla_tier_for(risk_score: float, is_kev: bool) -> str:
    """Return the SLA tier label for the given risk profile."""
    if is_kev:
        return TIER_KEV
    if risk_score >= CRITICAL_RISK_THRESHOLD:
        return TIER_CRITICAL
    if risk_score >= HIGH_RISK_THRESHOLD:
        return TIER_HIGH
    return TIER_STANDARD


def compute_sla_deadline(risk_score: float, is_kev: bool) -> datetime:
    """Compute the naive-UTC SLA deadline for a vulnerability."""
    days = sla_days_for(risk_score, is_kev)
    return datetime.now(UTC).replace(tzinfo=None) + timedelta(days=days)


def compute_sla_status(deadline: datetime, now: Optional[datetime] = None) -> Dict[str, object]:
    """
    Evaluate the SLA status for a deadline relative to now (naive UTC).

    Returns a dict with:
        status             - ON_TRACK | AT_RISK | ESCALATED | BREACHED
        escalation_required- True when within the 48h escalation window
        hours_remaining    - signed hours between now and the deadline
        tier               - derived tier label (best-effort, based on days)
    """
    now = now or datetime.now(UTC).replace(tzinfo=None)
    if deadline.tzinfo is not None:
        deadline = deadline.replace(tzinfo=None)
    if now.tzinfo is not None:
        now = now.replace(tzinfo=None)

    hours_remaining = (deadline - now).total_seconds() / 3600.0
    escalation_required = 0 < hours_remaining <= ESCALATION_WINDOW_HOURS

    if hours_remaining < 0:
        status = STATUS_BREACHED
    elif escalation_required:
        status = STATUS_ESCALATED
    elif hours_remaining <= ESCALATION_WINDOW_HOURS * 2:
        status = STATUS_AT_RISK
    else:
        status = STATUS_ON_TRACK

    days = max(int(hours_remaining / 24), 0)
    if days <= KEV_SLA_DAYS:
        tier = TIER_KEV
    elif days <= CRITICAL_SLA_DAYS:
        tier = TIER_CRITICAL
    elif days <= HIGH_SLA_DAYS:
        tier = TIER_HIGH
    else:
        tier = TIER_STANDARD

    return {
        "status": status,
        "escalation_required": escalation_required,
        "hours_remaining": round(hours_remaining, 2),
        "tier": tier,
        "deadline": deadline,
    }


def check_escalation(deadline: datetime, now: Optional[datetime] = None) -> bool:
    """Return True when the deadline is inside the 48h escalation window."""
    return bool(compute_sla_status(deadline, now)["escalation_required"])
