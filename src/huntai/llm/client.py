"""Chat client for the free-model stack, built on the official `openai` SDK.

NVIDIA NIM, Ollama, and Gemini all expose OpenAI-compatible endpoints, so one
lightweight SDK drives every provider — no litellm, no Rust build, installs on
Python 3.14. The SDK is a lazy, optional import; without it the LLM features
fall back to deterministic behavior.
"""

from __future__ import annotations

from ..config import Provider, Role, Settings, get_settings

# OpenAI-compatible base URLs per provider
_GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai/"


class LLMError(Exception):
    pass


class LLMClient:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()

    def available(self, role: Role = Role.REASONING) -> bool:
        provider, _ = self.settings.route(role)
        if provider is Provider.NVIDIA:
            return bool(self.settings.nvidia_api_key)
        if provider is Provider.GEMINI:
            return bool(self.settings.gemini_api_key)
        return True  # Ollama assumed reachable locally

    def _endpoint(self, role: Role) -> tuple[str, str, str]:
        """Return (base_url, api_key, model) for the routed provider."""
        provider, model = self.settings.route(role)
        s = self.settings
        if provider is Provider.NVIDIA:
            return s.nvidia_base_url, s.nvidia_api_key or "", model
        if provider is Provider.OLLAMA:
            base = s.ollama_host.rstrip("/") + "/v1"
            return base, (s.ollama_api_key or "ollama"), model
        if provider is Provider.GEMINI:
            return _GEMINI_BASE, s.gemini_api_key or "", model
        raise LLMError(f"unsupported provider {provider}")

    def complete(self, system: str, user: str, role: Role = Role.REASONING,
                 temperature: float = 0.2) -> str:
        try:
            from openai import OpenAI  # lazy, optional
        except ImportError as exc:
            raise LLMError("openai SDK not installed: pip install -e \".[llm]\"") from exc

        base_url, api_key, model = self._endpoint(role)
        try:
            client = OpenAI(base_url=base_url, api_key=api_key)
            resp = client.chat.completions.create(
                model=model,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": user}],
                temperature=temperature,
            )
            return resp.choices[0].message.content or ""
        except Exception as exc:  # network / auth / provider errors
            raise LLMError(str(exc)) from exc
