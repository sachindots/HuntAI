"""Multi-agent orchestration + Copilot mode tests."""

import asyncio
from pathlib import Path

import pytest

from huntai.agents import (
    AnalysisAgent,
    CopilotAgent,
    Orchestrator,
    ReconAgent,
    ReporterAgent,
    ValidationAgent,
)
from huntai.engine import Dispatcher, FakeRunner
from huntai.kb import FindingsMemory
from huntai.schemas import Severity
from huntai.scope import ScopeGuard
from huntai.tools import default_registry

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


def _orch():
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    disp = Dispatcher(FakeRunner(_fixtures()), default_registry())
    return Orchestrator(ReconAgent(disp, guard))


def test_auto_pipeline_end_to_end():
    orch = _orch()
    session = asyncio.run(orch.run_auto("172.20.0.10"))
    assert session.findings
    # high-severity nuclei finding must be validated by the validation pass
    highs = [f for f in session.findings if f.severity is Severity.HIGH]
    assert highs and all(f.validated for f in highs)
    assert orch.last_report["total_findings"] == len(session.findings)


def test_reporter_markdown():
    orch = _orch()
    session = asyncio.run(orch.run_auto("172.20.0.10"))
    md = ReporterAgent().markdown(session)
    assert md.startswith("# HuntAI Report")
    assert "Findings" in md


def test_analysis_dedups():
    from huntai.schemas import Finding, Session
    s = Session(name="t")
    s.findings = [
        Finding(title="open 80/tcp http", target="x", source_tool="nmap"),
        Finding(title="open 80/tcp http", target="x", source_tool="naabu"),
    ]
    AnalysisAgent().analyze(s)
    assert len(s.findings) == 1
    assert "corroborated_by" in s.findings[0].description


def test_validation_flags_info_low_confidence():
    from huntai.schemas import Finding, Session
    s = Session(name="t")
    s.findings = [Finding(title="banner", severity=Severity.INFO, target="x", confidence=0.9)]
    ValidationAgent().validate(s)
    assert s.findings[0].confidence <= 0.3
    assert s.findings[0].validated is False


# -- copilot ------------------------------------------------------------

def test_copilot_suggests_and_runs_nothing():
    cop = CopilotAgent()
    sug = cop.observe("nmap shows 80/tcp open apache httpd 2.4.7")
    assert "httpx" in sug.next_tools and "nuclei" in sug.next_tools
    with pytest.raises(RuntimeError):
        cop.run("172.20.0.10")


def test_copilot_grounds_in_memory():
    mem = FindingsMemory()
    mem.add("kb1", "apache php default credentials dvwa login")
    cop = CopilotAgent(memory=mem)
    sug = cop.observe("found apache php login page")
    assert "kb1" in sug.kb_refs


def test_copilot_no_signal():
    sug = CopilotAgent().observe("just some random text")
    assert sug.next_tools == []
