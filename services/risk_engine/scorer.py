"""
Deterministic Risk Scoring Engine.
Calculates vulnerability risk score based on CVSS base score, EPSS exploit prediction,
CISA Known Exploited Vulnerability (KEV) status, asset business criticality, and network exposure.
"""

from typing import Dict, Any

class RiskScorer:
    """
    Risk Score Formula:
    RiskScore = (CVSS * 0.30) + (EPSS * 10 * 0.25) + (KEV_Bonus * 0.20) + (Criticality * 0.15) + (Exposure * 0.10)
    Normalized to a 0.0 - 10.0 scale.
    """

    @staticmethod
    def calculate_risk_score(
        cvss_score: float,
        epss_score: float,
        is_known_exploited: bool,
        asset_criticality: int,  # 1-10
        exposure_level: str  # internet-facing, internal, isolated
    ) -> float:
        # 1. Base CVSS component (0.0 to 10.0) -> weight 30%
        cvss_component = min(max(cvss_score, 0.0), 10.0) * 0.30

        # 2. EPSS component (0.0 to 1.0 mapped to 0-10) -> weight 25%
        epss_component = min(max(epss_score, 0.0), 1.0) * 10.0 * 0.25

        # 3. KEV Known Exploited component (10.0 if True, else 0.0) -> weight 20%
        kev_component = (10.0 if is_known_exploited else 0.0) * 0.20

        # 4. Asset Criticality component (1 to 10) -> weight 15%
        criticality_component = min(max(asset_criticality, 1), 10) * 0.15

        # 5. Network Exposure component -> weight 10%
        exposure_multiplier = {
            "internet-facing": 10.0,
            "internal": 5.0,
            "isolated": 1.0
        }.get(exposure_level.lower(), 5.0)
        exposure_component = exposure_multiplier * 0.10

        # Total Weighted Score (Max 10.0)
        total_score = cvss_component + epss_component + kev_component + criticality_component + exposure_component
        return round(min(total_score, 10.0), 2)
