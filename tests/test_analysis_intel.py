"""Analysis intelligence tests — MITRE, CVE, attack graph."""

import asyncio
from pathlib import Path

from huntai.agents import Orchestrator, ReconAgent
from huntai.analysis import CVECorrelator, IntelligenceAgent, build_graph, map_techniques
from huntai.engine import Dispatcher, FakeRunner
from huntai.schemas import Finding, Session, Severity, Target, TargetKind
from huntai.scope import ScopeGuard
from huntai.tools import default_registry

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


# -- MITRE --------------------------------------------------------------

def test_mitre_tool_mapping():
    f = Finding(title="Apache Detection", target="x", source_tool="nuclei")
    assert "T1595.002" in map_techniques(f)


def test_mitre_keyword_mapping():
    f = Finding(title="DVWA Default Login", target="x", source_tool="nuclei")
    techs = map_techniques(f)
    assert "T1078" in techs  # valid accounts


# -- CVE ----------------------------------------------------------------

def test_cve_lookup_exact():
    c = CVECorrelator()
    assert "CVE-2014-0226" in c.lookup("Apache httpd", "2.4.7")


def test_cve_lookup_prefix():
    c = CVECorrelator()
    assert c.lookup("OpenSSH", "6.6.1p1")  # openssh 6.6.1p1 present


def test_cve_no_match():
    assert CVECorrelator().lookup("randomd", "9.9") == []


# -- graph --------------------------------------------------------------

def test_graph_mermaid():
    s = Session(name="g", targets=[Target(raw="172.20.0.10", kind=TargetKind.IP)])
    s.findings = [Finding(title="open 80/tcp http", severity=Severity.HIGH, target="172.20.0.10")]
    g = build_graph(s)
    m = g.to_mermaid()
    assert m.startswith("graph TD")
    assert "172.20.0.10" in m
    assert "style" in m  # severity styling on the finding node


# -- full enrich via orchestrator --------------------------------------

def test_intelligence_enriches_findings():
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    disp = Dispatcher(FakeRunner(_fixtures()), default_registry())
    orch = Orchestrator(ReconAgent(disp, guard), intelligence=IntelligenceAgent())
    session = asyncio.run(orch.run_auto("172.20.0.10"))

    # nmap fixture has apache 2.4.7 + openssh 6.6.1p1 -> CVEs correlated
    all_cves = {c for f in session.findings for c in f.cve_ids}
    assert "CVE-2014-0226" in all_cves
    # findings carry MITRE techniques
    assert any(f.mitre_techniques for f in session.findings)
    # attack graph builds
    assert IntelligenceAgent().graph(session).to_mermaid().startswith("graph TD")
