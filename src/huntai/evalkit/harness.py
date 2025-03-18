"""Benchmark harness + metrics."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from ..agents import Orchestrator, ReconAgent
from ..agents.validation import ValidationAgent
from ..analysis import IntelligenceAgent
from ..engine import Dispatcher
from ..engine.runner import ToolRunner
from ..schemas import Finding, Session
from ..scope import ScopeGuard
from ..tools import default_registry

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class Metrics:
    expected: int
    matched: int
    report_worthy: int
    true_positives: int
    false_positives: int
    coverage: float          # recall over expected
    precision: float         # over report-worthy findings
    f1: float

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _finding_text(f: Finding) -> str:
    return " ".join([
        f.title, f.evidence, f.target,
        " ".join(f.cve_ids), " ".join(f.mitre_techniques), f.severity.value,
    ]).lower()


def _matches(sig: str, text: str) -> bool:
    return all(tok in text for tok in sig.lower().split())


def evaluate(expected: list[str], findings: list[Finding], report_worthy: list[Finding]) -> Metrics:
    texts = [(_finding_text(f), f) for f in findings]

    matched = 0
    for sig in expected:
        if any(_matches(sig, txt) for txt, _ in texts):
            matched += 1

    rw_texts = [_finding_text(f) for f in report_worthy]
    tp = sum(1 for txt in rw_texts if any(_matches(sig, txt) for sig in expected))
    fp = len(rw_texts) - tp

    coverage = matched / len(expected) if expected else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * coverage / (precision + coverage)) if (precision + coverage) else 0.0
    return Metrics(len(expected), matched, len(report_worthy), tp, fp,
                   round(coverage, 3), round(precision, 3), round(f1, 3))


class EvalHarness:
    def __init__(self, runner: ToolRunner, guard: ScopeGuard | None = None) -> None:
        self.guard = guard or ScopeGuard.from_yaml(ROOT / "scope.yaml")
        self.orch = Orchestrator(
            ReconAgent(Dispatcher(runner, default_registry()), self.guard),
            intelligence=IntelligenceAgent(),
        )
        self.validator = ValidationAgent()

    async def run(self, groundtruth_path: str | Path) -> tuple[Session, Metrics]:
        gt = yaml.safe_load(Path(groundtruth_path).read_text(encoding="utf-8"))
        session = await self.orch.run_auto(gt["target"], name="eval")
        report_worthy = self.validator.report_worthy(session)
        metrics = evaluate(gt.get("expected", []), session.findings, report_worthy)
        return session, metrics
