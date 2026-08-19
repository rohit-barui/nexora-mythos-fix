"""
Multi-Provider LLM failover chain (Blueprint Pillar 3).

Implements the provider drivers (OpenAI, Anthropic, Google Gemini, local
Ollama) and a failover planner that walks the chain, retrying each provider
on transient errors or schema-violating output before switching.

Cost estimation uses the blueprint formula:
    Cost = (PromptTokens * $0.000005) + (CompletionTokens * $0.000015)
"""

import json
import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx

from services.llm_planner.schema import validate_remediation_plan_json

logger = logging.getLogger(__name__)

PROMPT_TOKEN_COST = 0.000005
COMPLETION_TOKEN_COST = 0.000015


def estimate_llm_cost(prompt_tokens: int, completion_tokens: int) -> float:
    """Estimate the USD cost of an LLM call using the blueprint pricing formula."""
    return round(
        (prompt_tokens * PROMPT_TOKEN_COST) + (completion_tokens * COMPLETION_TOKEN_COST),
        6,
    )


class LLMProvider(ABC):
    """Base class for an LLM provider driver."""

    name: str = "base"
    model: str = "base"

    @abstractmethod
    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        """Return the raw completion content for the given prompts."""


class OpenAIProvider(LLMProvider):
    name = "openai"
    api_url = "https://api.openai.com/v1/chat/completions"

    def __init__(self, api_key: str, model: str = "gpt-4o", timeout: float = 30.0) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.api_url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    api_url = "https://api.anthropic.com/v1/messages"

    def __init__(
        self, api_key: str, model: str = "claude-3-5-sonnet", timeout: float = 30.0
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
        body = {
            "model": self.model,
            "max_tokens": 500,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_prompt}],
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.api_url, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
            return "".join(block.get("text", "") for block in data.get("content", []))


class GeminiProvider(LLMProvider):
    name = "gemini"
    api_url = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str = "gemini-1.5-pro", timeout: float = 30.0) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        url = f"{self.api_url}/{self.model}:generateContent?key={self.api_key}"
        body = {
            "systemInstruction": {"parts": [{"text": system_prompt}]},
            "contents": [{"parts": [{"text": user_prompt}]}],
            "generationConfig": {"temperature": 0.0},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]


class OllamaProvider(LLMProvider):
    name = "ollama"
    api_url = "http://localhost:11434/api/chat"

    def __init__(
        self, base_url: str = "http://localhost:11434", model: str = "llama3", timeout: float = 60.0
    ) -> None:
        self.api_url = f"{base_url.rstrip('/')}/api/chat"
        self.model = model
        self.timeout = timeout

    async def generate(self, system_prompt: str, user_prompt: str) -> str:
        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "stream": False,
            "options": {"temperature": 0},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.api_url, json=body)
            resp.raise_for_status()
            data = resp.json()
            return data["message"]["content"]


class MultiProviderPlanner:
    """
    Failover LLM planner.

    Walks the configured provider chain, retrying each provider (up to
    max_retries) and validating output against the RemediationPlanSchema
    before switching to the next provider.
    """

    def __init__(
        self,
        providers: List[LLMProvider],
        max_retries: int = 3,
        fallback_plan_builder: Any = None,
    ) -> None:
        self.providers = providers
        self.max_retries = max_retries
        self.fallback_plan_builder = fallback_plan_builder

    async def generate_remediation_plan(
        self, system_prompt: str, user_prompt: str
    ) -> Dict[str, Any]:
        """Return a validated remediation plan dict, or fall back to the builder."""
        last_error: Optional[Exception] = None
        for provider in self.providers:
            for attempt in range(self.max_retries):
                try:
                    content = await provider.generate(system_prompt, user_prompt)
                    raw = json.loads(content)
                    validated = validate_remediation_plan_json(raw)
                    logger.info(
                        "Provider %s generated valid plan (attempt %d)",
                        provider.name,
                        attempt + 1,
                    )
                    return validated.model_dump()
                except Exception as exc:
                    last_error = exc
                    logger.warning(
                        "Provider %s attempt %d failed: %s",
                        provider.name,
                        attempt + 1,
                        exc,
                    )
            logger.warning("Provider %s exhausted retries, switching", provider.name)

        if self.fallback_plan_builder is not None:
            logger.warning("All providers failed; using deterministic fallback builder")
            return self.fallback_plan_builder()
        raise RuntimeError(f"All LLM providers failed: {last_error}")
