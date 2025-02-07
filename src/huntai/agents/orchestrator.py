"""Orchestrator — owns the pipeline across specialist agents.

Auto mode: recon → analysis → validation → report. Copilot mode: hands back an
advisory agent that runs nothing.
"""

from __future__ import annotations

from ..schemas import Mode, Session
from .analysis import AnalysisAgent
from .copilot import CopilotAgent
from .recon import ReconAgent
from .reporter import ReporterAgent
from .validation import ValidationAgent


class Orchestrator:
    def __init__(
        self,
        recon: ReconAgent,
        analysis: AnalysisAgent | None = None,
        validation: ValidationAgent | None = None,
        reporter: ReporterAgent | None = None,
        copilot: CopilotAgent | None = None,
        intelligence=None,
        llm_analyst=None,
    ) -> None:
        self.recon = recon
        self.analysis = analysis or AnalysisAgent()
        self.validation = validation or ValidationAgent()
        self.reporter = reporter or ReporterAgent()
        self.copilot = copilot or CopilotAgent()
        self.intelligence = intelligence  # optional IntelligenceAgent
        self.llm_analyst = llm_analyst    # optional LLMAnalyst
        self.last_report: dict | None = None

    async def run_auto(self, target: str, name: str = "assessment") -> Session:
        session = await self.recon.run(target, name=name)
        self.analysis.analyze(session)
        if self.intelligence is not None:
            self.intelligence.enrich(session)  # MITRE + CVE enrichment
        if self.llm_analyst is not None:
            self.llm_analyst.enrich(session)   # LLM remediation + risk notes
        self.validation.validate(session)
        self.last_report = self.reporter.report(session)
        if self.llm_analyst is not None:
            self.last_report["executive_summary"] = \
                self.llm_analyst.executive_summary(self.last_report)
        return session

    def as_copilot(self) -> CopilotAgent:
        return self.copilot

    def mode_agent(self, mode: Mode):
        return self.recon if mode is Mode.AUTO else self.copilot
