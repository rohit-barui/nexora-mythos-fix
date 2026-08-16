import pytest
from services.risk_engine.scorer import RiskScorer

def test_risk_scorer_high_criticality_and_kev():
    score = RiskScorer.calculate_risk_score(
        cvss_score=9.8,
        epss_score=0.95,
        is_known_exploited=True,
        asset_criticality=10,
        exposure_level="internet-facing"
    )
    assert score == 9.81

def test_risk_scorer_maximum_score():
    score = RiskScorer.calculate_risk_score(
        cvss_score=10.0,
        epss_score=1.0,
        is_known_exploited=True,
        asset_criticality=10,
        exposure_level="internet-facing"
    )
    assert score == 10.0

def test_risk_scorer_low_criticality():
    score = RiskScorer.calculate_risk_score(
        cvss_score=3.0,
        epss_score=0.01,
        is_known_exploited=False,
        asset_criticality=2,
        exposure_level="isolated"
    )
    assert 0.0 <= score <= 3.0
