"""CopilotAgent — the sideline / advisor mode.

User drives their own terminal; HuntAI watches what they paste (a tool output,
a port list, a target) and SUGGESTS the next move, grounded in the KB. It runs
NOTHING itself — no dispatch, no tools. Pure advice + explanation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..kb.cag import CAGStore
from ..kb.memory import FindingsMemory


@dataclass
class Suggestion:
    summary: str
    next_tools: list[str] = field(default_factory=list)
    rationale: str = ""
    kb_refs: list[str] = field(default_factory=list)


# keyword -> (suggested tools, why)
_RULES: list[tuple[re.Pattern, list[str], str]] = [
    (re.compile(r"\b80\b|\bhttp\b|\bapache\b|\bnginx\b|\bphp\b", re.I),
     ["httpx", "nuclei", "ffuf"], "HTTP service present — probe, fingerprint, discover content."),
    (re.compile(r"\b443\b|\bhttps\b|\btls\b|\bssl\b", re.I),
     ["httpx", "testssl", "nuclei"], "TLS endpoint — check cert + weak ciphers, then templates."),
    (re.compile(r"\b22\b|\bssh\b", re.I),
     ["nmap"], "SSH — fingerprint version for known CVEs; avoid brute force."),
    (re.compile(r"\bwordpress\b|\bwp-\b", re.I),
     ["wpscan"], "WordPress detected — enumerate plugins/themes for known vulns."),
    (re.compile(r"\bsubdomain\b|\bdns\b|domain", re.I),
     ["subfinder", "dnsx"], "Domain scope — passive subdomain enumeration first."),
]


class CopilotAgent:
    """Advises. Never executes."""

    def __init__(self, cag: CAGStore | None = None, memory: FindingsMemory | None = None) -> None:
        self.cag = cag
        self.memory = memory

    def observe(self, observation: str) -> Suggestion:
        tools: list[str] = []
        why: list[str] = []
        for pattern, tls, reason in _RULES:
            if pattern.search(observation):
                for t in tls:
                    if t not in tools:
                        tools.append(t)
                why.append(reason)

        kb_refs: list[str] = []
        if self.memory is not None:
            kb_refs = [d.id for d in self.memory.retrieve(observation, k=3)]

        if not tools:
            return Suggestion(
                summary="No obvious next step from that output.",
                rationale="Share more context (ports, tech, response) for a targeted suggestion.",
                kb_refs=kb_refs,
            )
        return Suggestion(
            summary=f"Suggested next: {', '.join(tools)}",
            next_tools=tools,
            rationale=" ".join(why),
            kb_refs=kb_refs,
        )

    # explicit guarantee for callers/tests: copilot cannot run tools
    def run(self, *_a, **_k):  # noqa: D401
        raise RuntimeError("Copilot mode is advisory only; switch to Auto mode to execute.")
