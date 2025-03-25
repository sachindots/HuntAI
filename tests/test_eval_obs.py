"""Eval harness + observability tracer tests."""

import asyncio
import time
from pathlib import Path

from huntai.engine import FakeRunner
from huntai.evalkit import EvalHarness, evaluate
from huntai.obs import Tracer
from huntai.schemas import Finding, Severity

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"
GT = ROOT / "eval" / "groundtruth" / "lab-172.20.0.10.yaml"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


def test_evaluate_units():
    findings = [
        Finding(title="open 80/tcp http", target="x", cve_ids=["CVE-2014-0226"]),
        Finding(title="DVWA Default Login", severity=Severity.HIGH, target="x"),
    ]
    m = evaluate(["80", "default login", "CVE-2014-0226"], findings, findings)
    assert m.coverage == 1.0
    assert m.precision == 1.0


def test_harness_on_lab_fixture():
    h = EvalHarness(FakeRunner(_fixtures()))
    session, m = asyncio.run(h.run(GT))
    assert session.findings
    # all four ground-truth items should be discovered
    assert m.coverage == 1.0
    assert m.matched == m.expected == 4
    assert 0.0 <= m.precision <= 1.0
    assert m.f1 > 0.5


def test_tracer_records_spans():
    tr = Tracer()
    with tr.span("recon", target="x") as s:
        s.tokens = 120
        time.sleep(0.005)
    assert len(tr.spans) == 1
    assert tr.spans[0].duration_ms > 0
    assert tr.total_tokens() == 120
    assert tr.summary()[0]["name"] == "recon"
