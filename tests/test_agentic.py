"""AgenticReconAgent tests — LLM-driven iterative orchestration + safety rails.
A queue-based fake client returns successive decisions; no network needed."""

import asyncio
from pathlib import Path

from huntai.agents import AgenticReconAgent
from huntai.agents.planner import RuleBasedPlanner
from huntai.engine import Dispatcher, FakeRunner
from huntai.llm.client import LLMError
from huntai.schemas import ToolStatus
from huntai.scope import ScopeError, ScopeGuard
from huntai.tools import default_registry

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


class QueueClient:
    """Returns queued replies in order; raises if a reply is an Exception."""
    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = 0

    def complete(self, system, user, role=None, temperature=0.2):
        self.calls += 1
        if not self.replies:
            raise LLMError("no more replies")
        r = self.replies.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _agent(client, **kw):
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    disp = Dispatcher(FakeRunner(_fixtures()), default_registry())
    return AgenticReconAgent(disp, guard, default_registry(), client=client, **kw)


def test_iterative_loop_runs_then_stops():
    client = QueueClient([
        '{"tools":[{"tool":"naabu"},{"tool":"nmap"}],"done":false}',
        '{"tools":[{"tool":"httpx"},{"tool":"nuclei"}],"done":false}',
        '{"tools":[],"done":true}',
    ])
    session = asyncio.run(_agent(client).run("172.20.0.10"))
    ran = {r.tool for r in session.tool_results if r.status is ToolStatus.SUCCESS}
    assert {"naabu", "nmap", "httpx", "nuclei"} <= ran
    assert session.findings


def test_stops_on_done_immediately():
    client = QueueClient(['{"tools":[{"tool":"naabu"}],"done":true}'])
    session = asyncio.run(_agent(client).run("172.20.0.10"))
    assert {r.tool for r in session.tool_results} == {"naabu"}


def test_unknown_tool_filtered():
    client = QueueClient(['{"tools":[{"tool":"metasploit"},{"tool":"nmap"}],"done":true}'])
    session = asyncio.run(_agent(client).run("172.20.0.10"))
    assert {r.tool for r in session.tool_results} == {"nmap"}


def test_scope_enforced():
    client = QueueClient(['{"tools":[{"tool":"nmap"}],"done":true}'])
    with pytest.raises(ScopeError):
        asyncio.run(_agent(client).run("8.8.8.8"))


def test_max_iters_cap():
    # never returns done -> must stop at max_iters, not loop forever
    client = QueueClient(['{"tools":[{"tool":"nmap"}],"done":false}'] * 50)
    asyncio.run(_agent(client, max_iters=3).run("172.20.0.10"))
    assert client.calls <= 4  # first decision + up to max_iters follow-ups


def test_fallback_when_llm_unavailable():
    # first decision raises -> deterministic RuleBasedPlanner path
    client = QueueClient([LLMError("no key")])
    session = asyncio.run(_agent(client).run("172.20.0.10"))
    ran = {r.tool for r in session.tool_results if r.status is ToolStatus.SUCCESS}
    expected = {s.tool for s in RuleBasedPlanner().plan("172.20.0.10")}
    assert ran == expected & ran and "nmap" in ran
