"""LLMPlanner — live LLM-driven recon planning with hard safety rails.

The LLM output is UNTRUSTED. We accept only tool names that exist in the
registry, filter opts to a per-tool whitelist, force passive-first ordering,
and fall back to the deterministic RuleBasedPlanner on any error (no key,
offline, bad JSON, empty plan). Scope is still enforced downstream by the agent.
"""

from __future__ import annotations

import json
import re

from ..config import Role
from ..kb.cag import CAGStore
from ..llm.client import LLMClient, LLMError
from ..scope import ScopeGuard
from ..tools.registry import ToolRegistry
from .planner import Planner, ReconStep, RuleBasedPlanner
from .prompts import PLANNER_SYSTEM, planner_user

# per-tool allowed opt keys + coercers — anything else is dropped
_OPT_WHITELIST = {
    "nmap": {"ports": str},
    "naabu": {"top_ports": int},
    "nuclei": {"severity": str},
}
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


class LLMPlanner:
    def __init__(
        self,
        registry: ToolRegistry,
        client: LLMClient | None = None,
        cag: CAGStore | None = None,
        fallback: Planner | None = None,
    ) -> None:
        self.registry = registry
        self.client = client or LLMClient()
        self.cag = cag
        self.fallback = fallback or RuleBasedPlanner()

    def plan(self, target: str) -> list[ReconStep]:
        try:
            return self._llm_plan(target)
        except (LLMError, ValueError, KeyError, json.JSONDecodeError):
            return self.fallback.plan(target)

    # -- internals ------------------------------------------------------

    def _llm_plan(self, target: str) -> list[ReconStep]:
        kind = ScopeGuard.classify(target).kind.value
        tools = [{"name": t.name, "category": t.category, "passive": t.passive}
                 for t in self.registry.all()]
        kb = self.cag.context if self.cag else ""
        raw = self.client.complete(PLANNER_SYSTEM, planner_user(target, kind, tools, kb),
                                   role=Role.REASONING)
        steps = self._validate(raw, target)
        if not steps:
            raise ValueError("empty plan after validation")
        # safety: passive tools always first regardless of model ordering
        steps.sort(key=lambda s: (not s.passive))
        return steps

    def _validate(self, raw: str, target: str) -> list[ReconStep]:
        data = json.loads(_extract_json(raw))
        plan = data.get("plan", []) if isinstance(data, dict) else data
        steps: list[ReconStep] = []
        seen: set[str] = set()
        for item in plan:
            name = (item or {}).get("tool")
            if not name or name in seen:
                continue
            try:
                tool = self.registry.get(name)  # rejects unknown/dangerous tools
            except KeyError:
                continue
            seen.add(name)
            steps.append(ReconStep(
                tool=name, target=target, passive=tool.passive,
                opts=_clean_opts(name, (item or {}).get("opts") or {}),
            ))
        return steps


def _extract_json(text: str) -> str:
    text = text.strip()
    # tolerate models that wrap JSON in prose / code fences
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return m.group(0) if m else text


def _clean_opts(tool: str, opts: dict) -> dict:
    allowed = _OPT_WHITELIST.get(tool, {})
    out: dict = {}
    for key, coerce in allowed.items():
        if key not in opts:
            continue
        try:
            val = coerce(opts[key])
        except (TypeError, ValueError):
            continue
        if tool == "nuclei" and key == "severity" and val not in _SEVERITIES:
            continue
        out[key] = val
    return out
