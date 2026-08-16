"""Configuration loader for the LLM Planner guardrails (config.json)."""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


@dataclass(frozen=True)
class LLMPlannerLimits:
    """Bounded guardrails applied to every LLM planner invocation."""

    max_drift_percent: float = 5.0
    max_hallucination_score: float = 0.1
    max_token_usage: int = 2000
    max_response_tokens: int = 500
    model: str = "gpt-4o-mini"
    reasoning_enabled: bool = False

    @classmethod
    def from_file(cls, path: Optional[str] = None) -> "LLMPlannerLimits":
        """Load limits from config.json, falling back to defaults on any error."""
        config_path = Path(path) if path else Path(__file__).resolve().parents[2] / "config.json"
        try:
            raw = json.loads(config_path.read_text(encoding="utf-8"))
            limits = raw.get("limits", {})
            model_cfg = raw.get("model_selection", {}).get("default", {})
            return cls(
                max_drift_percent=float(limits.get("max_drift_percent", 5.0)),
                max_hallucination_score=float(limits.get("max_hallucination_score", 0.1)),
                max_token_usage=int(limits.get("max_token_usage", 2000)),
                max_response_tokens=int(limits.get("max_response_tokens", 500)),
                model=str(model_cfg.get("model", "gpt-4o-mini")),
                reasoning_enabled=bool(raw.get("reasoning_enabled", False)),
            )
        except (OSError, ValueError, TypeError):
            return cls()
