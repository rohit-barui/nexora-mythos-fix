from services.risk_engine.scorer import RiskScorer


def test_risk_scorer_high_criticality_and_kev():
    score = RiskScorer.calculate_risk_score(
        cvss_score=9.8,
        epss_score=0.95,
        is_known_exploited=True,
        asset_criticality=10,
        exposure_level="internet-facing",
    )
    assert score == 9.81


def test_risk_scorer_maximum_score():
    score = RiskScorer.calculate_risk_score(
        cvss_score=10.0,
        epss_score=1.0,
        is_known_exploited=True,
        asset_criticality=10,
        exposure_level="internet-facing",
    )
    assert score == 10.0


def test_risk_scorer_low_criticality():
    score = RiskScorer.calculate_risk_score(
        cvss_score=3.0,
        epss_score=0.01,
        is_known_exploited=False,
        asset_criticality=2,
        exposure_level="isolated",
    )
    assert 0.0 <= score <= 3.0


def test_risk_scorer_clamps_out_of_range_inputs():
    score = RiskScorer.calculate_risk_score(
        cvss_score=15.0,  # Above max CVSS
        epss_score=2.5,  # Above max EPSS
        is_known_exploited=True,
        asset_criticality=50,  # Above max criticality
        exposure_level="internet-facing",
    )
    assert score == 10.0


def test_risk_scorer_negative_inputs_floor_at_zero():
    score = RiskScorer.calculate_risk_score(
        cvss_score=-5.0,
        epss_score=-1.0,
        is_known_exploited=False,
        asset_criticality=1,
        exposure_level="isolated",
    )
    assert score >= 0.0


def test_risk_scorer_exposure_levels_ranked():
    internet = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "internet-facing")
    internal = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "internal")
    isolated = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "isolated")
    assert internet > internal > isolated


def test_risk_scorer_kev_flag_increases_score():
    no_kev = RiskScorer.calculate_risk_score(7.0, 0.5, False, 5, "internal")
    kev = RiskScorer.calculate_risk_score(7.0, 0.5, True, 5, "internal")
    assert kev > no_kev


def test_risk_scorer_unknown_exposure_defaults_to_internal():
    score = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "dmz")
    internal = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "internal")
    assert score == internal


def test_risk_scorer_exposure_case_insensitive():
    upper = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "INTERNET-FACING")
    lower = RiskScorer.calculate_risk_score(9.0, 0.5, False, 5, "internet-facing")
    assert upper == lower


def test_risk_scorer_returns_rounded_score():
    score = RiskScorer.calculate_risk_score(9.8, 0.95, True, 10, "internet-facing")
    assert score == round(score, 2)
