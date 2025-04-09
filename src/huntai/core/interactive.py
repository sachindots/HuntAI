"""Interactive recon session — human-in-the-loop, step by step.

Instead of the agent running the whole engagement autonomously, an interactive
session exposes the loop as discrete steps the CLI or web drive:

    start(target)  -> scope-check, open a session
    propose()      -> the LLM suggests the next tool(s) + why  (runs nothing)
    run(tools)     -> execute ONLY the tools the human approved
    (repeat propose/run until the LLM says done, or the human stops)
    finalize()     -> analysis + MITRE/CVE + validation + report

This is the "not going berserk" model: HuntAI advises each step; the human
decides what actually executes.
"""

from __future__ import annotations

from ..agents.agentic import AgenticReconAgent
from ..agents.recon import findings_from_result
from ..engine.dispatcher import Job
from ..schemas import Mode, Session, Target, ToolStatus


class InteractiveRecon:
    def __init__(self, engine) -> None:
        from ..tools import default_registry
        self.engine = engine
        self.orch = engine.orchestrator
        self.agent = self.orch.recon              # AgenticReconAgent when use_llm
        self.dispatcher = self.agent.dispatcher
        self.registry = getattr(self.agent, "registry", None) or default_registry()
        self.session: Session | None = None
        self.target: Target | None = None
        self.executed: list[str] = []
        self.digest: str = ""
        self.step_no: int = 0

    # -- lifecycle ------------------------------------------------------

    def start(self, target: str, name: str = "interactive") -> Target:
        self.target = self.engine.guard.check(target)   # raises ScopeError if OOS
        self.session = Session(name=name, mode=Mode.AUTO, targets=[self.target])
        return self.target

    async def propose(self) -> dict:
        """Ask the LLM what to run next. Executes nothing."""
        assert self.target is not None
        decision = None
        if hasattr(self.agent, "_decide"):
            try:
                decision = self.agent._decide(self.target.raw, self.executed, self.digest)
            except Exception:
                decision = None
        if decision is None:
            # deterministic fallback: suggest the next unrun tool in standard order
            from ..agents.planner import RuleBasedPlanner
            remaining = [s.tool for s in RuleBasedPlanner().plan(self.target.raw)
                         if s.tool not in self.executed]
            decision = {"tools": [{"tool": t} for t in remaining[:1]],
                        "done": not remaining,
                        "rationale": "Standard recon order (no LLM configured)."}
        # only surface tools that actually exist in the registry
        known = {t.name for t in self.registry.all()}
        decision["tools"] = [item for item in (decision.get("tools") or [])
                             if (item or {}).get("tool") in known]
        return decision

    async def run(self, tools: list[str], opts: dict | None = None) -> dict:
        """Run ONLY the approved tool names. Returns their results + running findings."""
        assert self.session is not None and self.target is not None
        self.step_no += 1
        jobs = []
        for name in tools:
            try:
                self.registry.get(name)  # validate — unknown tools rejected
            except KeyError:
                continue
            jobs.append(Job(name, self.target.raw, opts=(opts or {}).get(name, {})))
        if not jobs:
            return {"results": [], "findings": len(self.session.findings)}

        results, digest = await self.dispatcher.run_batch(jobs)
        self.session.tool_results.extend(results)
        self.digest = digest
        for r in results:
            if r.status is ToolStatus.SUCCESS:
                self.executed.append(r.tool)
            self.session.findings.extend(findings_from_result(r))

        return {
            "step": self.step_no,
            "results": [{"tool": r.tool, "status": r.status.value,
                         "summary": r.summary, "error": r.error} for r in results],
            "findings": len(self.session.findings),
        }

    def finalize(self) -> dict:
        """Run analysis + intelligence + validation + report on what was gathered."""
        assert self.session is not None
        self.orch.analysis.analyze(self.session)
        if self.orch.intelligence:
            self.orch.intelligence.enrich(self.session)
        if self.orch.llm_analyst:
            self.orch.llm_analyst.enrich(self.session)
        self.orch.validation.validate(self.session)
        report = self.orch.reporter.report(self.session)
        if self.orch.llm_analyst:
            report["executive_summary"] = self.orch.llm_analyst.executive_summary(report)
        return report
