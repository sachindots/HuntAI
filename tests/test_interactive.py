"""Interactive recon session — the human-in-the-loop, step-by-step flow."""

import asyncio
from pathlib import Path

import pytest

from huntai.core import build_engine
from huntai.core.interactive import InteractiveRecon
from huntai.engine import FakeRunner
from huntai.scope import ScopeError

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


def _session():
    engine = build_engine(runner=FakeRunner(_fixtures()), use_llm=False)
    return InteractiveRecon(engine)


def test_start_scope_check():
    ir = _session()
    t = ir.start("172.20.0.10")
    assert t.raw == "172.20.0.10"


def test_start_rejects_out_of_scope():
    with pytest.raises(ScopeError):
        _session().start("8.8.8.8")


def test_propose_runs_nothing():
    ir = _session()
    ir.start("172.20.0.10")
    proposal = asyncio.run(ir.propose())
    assert proposal["tools"]                      # suggests something
    assert ir.session.tool_results == []          # but executed nothing


def test_step_runs_only_approved():
    ir = _session()
    ir.start("172.20.0.10")
    out = asyncio.run(ir.run(["nmap"]))           # human approves ONLY nmap
    ran = {r["tool"] for r in out["results"]}
    assert ran == {"nmap"}                          # nothing else ran


def test_unknown_tool_rejected_in_step():
    ir = _session()
    ir.start("172.20.0.10")
    out = asyncio.run(ir.run(["metasploit", "nmap"]))
    assert {r["tool"] for r in out["results"]} == {"nmap"}


def test_full_interactive_flow():
    ir = _session()
    ir.start("172.20.0.10")
    asyncio.run(ir.run(["naabu"]))
    asyncio.run(ir.run(["nmap"]))
    asyncio.run(ir.run(["httpx", "nuclei"]))
    report = ir.finalize()
    assert report["total_findings"] > 0
    # findings enriched during finalize
    assert any(f["mitre_techniques"] for f in report["findings"])
