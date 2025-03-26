"""LLM client — free providers via LiteLLM (NVIDIA NIM / Ollama / Gemini).

LiteLLM is an optional dependency; the client imports it lazily so the rest of
HuntAI runs without it. Providers/models are chosen by `config.Settings.route`.
"""

from .client import LLMClient, LLMError

__all__ = ["LLMClient", "LLMError"]
