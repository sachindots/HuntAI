"""Minimal span tracer.

Wrap agent/tool calls in `tracer.span(name)` to record duration and token cost.
Zero deps; if `langfuse` is installed and configured, spans are also forwarded.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field


@dataclass
class Span:
    name: str
    start: float
    end: float | None = None
    tokens: int = 0
    meta: dict = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        return round(((self.end or time.perf_counter()) - self.start) * 1000, 2)


class Tracer:
    def __init__(self, export_langfuse: bool = False) -> None:
        self.spans: list[Span] = []
        self._langfuse = None
        if export_langfuse:
            try:
                from langfuse import Langfuse  # type: ignore
                self._langfuse = Langfuse()
            except Exception:
                self._langfuse = None

    @contextmanager
    def span(self, name: str, **meta):
        s = Span(name=name, start=time.perf_counter(), meta=meta)
        self.spans.append(s)
        try:
            yield s
        finally:
            s.end = time.perf_counter()
            if self._langfuse is not None:
                try:
                    self._langfuse.trace(name=name, metadata={
                        "duration_ms": s.duration_ms, "tokens": s.tokens, **s.meta})
                except Exception:
                    pass

    def total_tokens(self) -> int:
        return sum(s.tokens for s in self.spans)

    def summary(self) -> list[dict]:
        return [{"name": s.name, "ms": s.duration_ms, "tokens": s.tokens} for s in self.spans]
