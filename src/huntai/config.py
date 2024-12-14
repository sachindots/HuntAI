"""Configuration + model routing.

Free-model stack only: NVIDIA NIM (reasoning) with Ollama fallback, plus a
cheap local model for high-volume parsing. No paid cloud providers. Roles map
to providers here so the rest of the code never hardcodes a model.
"""

from __future__ import annotations

from enum import Enum

from pydantic_settings import BaseSettings, SettingsConfigDict


class Provider(str, Enum):
    NVIDIA = "nvidia"   # build.nvidia.com NIM, OpenAI-compatible, free tier
    OLLAMA = "ollama"   # local, fully offline fallback
    GEMINI = "gemini"   # google free tier, long-context / CAG


class Role(str, Enum):
    REASONING = "reasoning"   # orchestrator / planning
    PARSING = "parsing"       # cheap high-volume tool-output parsing
    LONGCTX = "longctx"       # CAG over the cheatsheet KB
    EMBED = "embed"           # embeddings


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="HUNTAI_", env_file=".env", extra="ignore"
    )

    # credentials (free)
    nvidia_api_key: str | None = None
    gemini_api_key: str | None = None
    ollama_api_key: str | None = None   # only for remote / auth-gated Ollama
    ollama_host: str = "http://localhost:11434"
    nvidia_base_url: str = "https://integrate.api.nvidia.com/v1"

    # model ids per provider
    nvidia_reasoning_model: str = "nvidia/nemotron-3-ultra-550b-a55b"
    nvidia_parsing_model: str = "meta/llama-3.1-8b-instruct"
    ollama_reasoning_model: str = "qwen3:8b"
    ollama_parsing_model: str = "qwen3:4b"
    ollama_embed_model: str = "bge-m3"
    gemini_longctx_model: str = "gemini-2.0-flash"

    scope_file: str = "scope.yaml"
    data_dir: str = "./data"
    prefer_offline: bool = False  # force Ollama-only

    # comma-separated targets to add to scope, e.g.
    #   HUNTAI_ALLOWED_TARGETS="10.0.0.5, example.lab, https://app.example.com"
    allowed_targets: str = ""

    def allowed_list(self) -> list[str]:
        return [t.strip() for t in self.allowed_targets.split(",") if t.strip()]

    def route(self, role: Role) -> tuple[Provider, str]:
        """Pick (provider, model) for a role, honoring fallbacks.

        Reasoning: NVIDIA NIM -> Ollama if no key / offline.
        Parsing:   Ollama by default (private, free, high volume).
        Longctx:   Gemini free -> Ollama if no key.
        Embed:     Ollama.
        """
        offline = self.prefer_offline
        if role is Role.REASONING:
            if not offline and self.nvidia_api_key:
                return Provider.NVIDIA, self.nvidia_reasoning_model
            return Provider.OLLAMA, self.ollama_reasoning_model
        if role is Role.PARSING:
            return Provider.OLLAMA, self.ollama_parsing_model
        if role is Role.LONGCTX:
            if not offline and self.gemini_api_key:
                return Provider.GEMINI, self.gemini_longctx_model
            return Provider.OLLAMA, self.ollama_reasoning_model
        return Provider.OLLAMA, self.ollama_embed_model


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        s = Settings()  # env + .env
        # overlay runtime settings the user set from the app
        try:
            from .core.settings_store import SettingsStore
            store = SettingsStore().load()
            for k in ("nvidia_api_key", "gemini_api_key", "ollama_api_key",
                      "ollama_host", "prefer_offline"):
                if store.get(k) not in (None, ""):
                    setattr(s, k, store[k])
        except Exception:
            pass
        _settings = s
    return _settings


def reset_settings() -> None:
    """Drop the cached settings so the next get_settings() re-reads the store."""
    global _settings
    _settings = None
