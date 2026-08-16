import json

from services.llm_planner.config import LLMPlannerLimits


def test_loads_defaults_when_config_missing(tmp_path):
    limits = LLMPlannerLimits.from_file(str(tmp_path / "missing.json"))
    assert limits.max_drift_percent == 5.0
    assert limits.max_hallucination_score == 0.1
    assert limits.max_token_usage == 2000
    assert limits.max_response_tokens == 500
    assert limits.model == "gpt-4o-mini"
    assert limits.reasoning_enabled is False


def test_loads_config_values(tmp_path):
    cfg = {
        "reasoning_enabled": True,
        "limits": {
            "max_drift_percent": 2,
            "max_hallucination_score": 0.05,
            "max_token_usage": 1500,
            "max_response_tokens": 300,
        },
        "model_selection": {"default": {"model": "gpt-4o", "cost_per_1k": 0.01}},
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    limits = LLMPlannerLimits.from_file(str(cfg_path))
    assert limits.max_drift_percent == 2.0
    assert limits.max_hallucination_score == 0.05
    assert limits.max_token_usage == 1500
    assert limits.max_response_tokens == 300
    assert limits.model == "gpt-4o"
    assert limits.reasoning_enabled is True


def test_falls_back_on_malformed_config(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("{not valid json", encoding="utf-8")
    limits = LLMPlannerLimits.from_file(str(bad_path))
    assert limits == LLMPlannerLimits()
