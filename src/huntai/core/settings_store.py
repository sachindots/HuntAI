"""Runtime settings store — lets the user configure keys and authorized targets
from inside the app (web/CLI), not just .env.

Persists to `data/settings.json` (gitignored). Holds free-model keys, Ollama
host/key, offline flag, and an explicit list of AUTHORIZED targets the user has
attested they may test. Adding a target requires an authorization acknowledgment
— the scope guard still denies metadata/CGNAT ranges regardless.
"""

from __future__ import annotations

import json
from pathlib import Path

_KEYS = ("nvidia_api_key", "gemini_api_key", "ollama_api_key")
_SETTABLE = _KEYS + ("ollama_host", "prefer_offline")


class SettingsStore:
    def __init__(self, path: str | Path = "data/settings.json") -> None:
        self.path = Path(path)

    def load(self) -> dict:
        if not self.path.exists():
            return {}
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def update(self, patch: dict) -> dict:
        data = self.load()
        for k, v in patch.items():
            if k in _SETTABLE:
                data[k] = v
        self._write(data)
        return data

    def masked(self) -> dict:
        """Config view safe to send to the UI — secrets shown only as set/unset."""
        data = self.load()
        out = {}
        for k in _SETTABLE:
            v = data.get(k)
            if k in _KEYS:
                out[k] = _mask(v)
            else:
                out[k] = v
        out["authorized_targets"] = data.get("authorized_targets", [])
        return out

    # -- authorized targets --------------------------------------------

    def add_authorized_target(self, target: str, authorized: bool) -> list[str]:
        if not authorized:
            raise PermissionError(
                "authorization acknowledgment required before adding a target")
        data = self.load()
        targets = data.get("authorized_targets", [])
        t = target.strip()
        if t and t not in targets:
            targets.append(t)
        data["authorized_targets"] = targets
        self._write(data)
        return targets

    def remove_authorized_target(self, target: str) -> list[str]:
        data = self.load()
        targets = [t for t in data.get("authorized_targets", []) if t != target.strip()]
        data["authorized_targets"] = targets
        self._write(data)
        return targets

    def authorized_targets(self) -> list[str]:
        return self.load().get("authorized_targets", [])


def _mask(v: str | None) -> str:
    if not v:
        return ""
    return f"set ...{v[-4:]}" if len(v) >= 4 else "set"
