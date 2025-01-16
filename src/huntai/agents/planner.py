"""Recon planners.

RuleBasedPlanner is deterministic (passive first, then active), used as the
safe default and in tests. An LLM planner (NVIDIA NIM / Ollama via config
routing) plugs in behind the same `Planner` protocol in later work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..scope import ScopeGuard
from ..schemas import TargetKind


@dataclass
class ReconStep:
    tool: str
    target: str
    passive: bool
    opts: dict = field(default_factory=dict)


class Planner(Protocol):
    def plan(self, target: str) -> list[ReconStep]:
        ...


class RuleBasedPlanner:
    """Deterministic recon chain. Passive OSINT first, then active scans."""

    def plan(self, target: str) -> list[ReconStep]:
        kind = ScopeGuard.classify(target).kind
        steps: list[ReconStep] = []

        if kind is TargetKind.DOMAIN:
            steps.append(ReconStep("subfinder", target, passive=True))
        # active chain (host/ip/url)
        steps.append(ReconStep("naabu", target, passive=False))
        steps.append(ReconStep("nmap", target, passive=False))
        steps.append(ReconStep("httpx", target, passive=False))
        steps.append(ReconStep("nuclei", target, passive=False))
        return steps
