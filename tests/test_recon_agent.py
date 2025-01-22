"""ReconAgent (Auto mode) tests — scope gate, approval gate, findings."""

import asyncio
from pathlib import Path

import pytest

from huntai.agents import ReconAgent, auto_approve, deny_all
from huntai.agents.approval import approve_only
from huntai.engine import Dispatcher, FakeRunner
from huntai.schemas import Mode, Severity, TaskStatus, ToolStatus
from huntai.scope import ScopeError, ScopeGuard
from huntai.tools import default_registry

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


def _agent(approval=auto_approve):
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    disp = Dispatcher(FakeRunner(_fixtures()), default_registry())
    return ReconAgent(disp, guard, approval=approval)


def test_auto_mode_full_run():
    session = asyncio.run(_agent().run("172.20.0.10"))
    assert session.mode is Mode.AUTO
    tools_run = {r.tool for r in session.tool_results if r.status is ToolStatus.SUCCESS}
    assert {"naabu", "nmap", "httpx", "nuclei"} <= tools_run
    # nuclei high finding + nmap port findings present
    sevs = {f.severity for f in session.findings}
    assert Severity.HIGH in sevs


def test_out_of_scope_refused():
    with pytest.raises(ScopeError):
        asyncio.run(_agent().run("8.8.8.8"))


def test_denied_tools_not_run():
    session = asyncio.run(_agent(approval=deny_all).run("172.20.0.10"))
    # all active tools denied -> no successful active results
    assert all(r.tool == "subfinder" or r.status is not ToolStatus.SUCCESS
               for r in session.tool_results) or not session.tool_results
    na = [t for t in session.tasks if t.status is TaskStatus.NA]
    assert len(na) >= 4


def test_partial_approval():
    session = asyncio.run(_agent(approval=approve_only("nmap")).run("172.20.0.10"))
    ran = {r.tool for r in session.tool_results}
    assert "nmap" in ran
    assert "nuclei" not in ran


def test_domain_adds_passive_subfinder():
    session = asyncio.run(_agent().run("scanme.huntai.lab"))
    assert any(t.assigned_tool == "subfinder" for t in session.tasks)
