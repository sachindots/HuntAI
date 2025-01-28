"""Cache-Augmented Generation store — the REAL thing.

Preloads a bounded, static methodology KB into one context blob and exposes a
stable cache key. A long-context model (Gemini free / local) loads this once
and reuses the KV cache across turns — no per-query retrieval. This is
appropriate precisely because the cheatsheet is small and stable.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


class CAGStore:
    def __init__(self, kb_dir: str | Path) -> None:
        self.kb_dir = Path(kb_dir)
        self._blob: str | None = None
        self._key: str | None = None

    def load(self) -> "CAGStore":
        parts: list[str] = []
        for md in sorted(self.kb_dir.rglob("*.md")):
            rel = md.relative_to(self.kb_dir)
            parts.append(f"\n\n===== {rel} =====\n{md.read_text(encoding='utf-8')}")
        self._blob = "".join(parts).strip()
        self._key = hashlib.sha256(self._blob.encode("utf-8")).hexdigest()[:16]
        return self

    @property
    def context(self) -> str:
        """The full preloaded cheatsheet, injected as system context once."""
        if self._blob is None:
            self.load()
        return self._blob or ""

    @property
    def cache_key(self) -> str:
        """Stable key — identifies this KV cache. Changes only if KB changes."""
        if self._key is None:
            self.load()
        return self._key or ""

    def token_estimate(self) -> int:
        return max(1, len(self.context) // 4)
