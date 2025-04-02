"""AgenticReconAgent — the LLM actually orchestrates.

Instead of a fixed plan, the LLM runs an iterative loop: it sees the target and
the compacted results so far, decides the next tools, and continues until it
declares recon complete (or a budget/iteration cap trips). This is HuntAI's
core aim — LLM-driven orchestration — with the same safety rails as the rest:
scope enforced, tool names validated against the registry, active tools gated
by human approval, passive-first, and a deterministic fallback on any LLM error.

Exposes the same `run(target, name) -> Session` interface as ReconAgent so the
Orchestrator uses it transparently.
"""

from __future__ import annotations

import json
import re

from ..audit import AuditLog
from ..config import Role
from ..engine.dispatcher import Dispatcher, Job
from ..kb.cag import CAGStore
from ..llm.client import LLMClient, LLMError
from ..schemas import Mode, Session, Target, Task, TaskStatus, ToolStatus
from ..scope import ScopeGuard
from ..tools.registry import ToolRegistry
from .approval import ApprovalGate, auto_approve
from .llm_planner import _clean_opts
from .prompts import ORCHESTRATOR_SYSTEM, orchestrator_user
from .recon import ReconAgent, findings_from_result
from .planner import RuleBasedPlanner


class AgenticReconAgent:
    def __init__(
        self,
        dispatcher: Dispatcher,
        guard: ScopeGuard,
        registry: ToolRegistry,
        client: LLMClient | None = None,
        cag: CAGStore | None = None,
        approval: ApprovalGate = auto_approve,
        audit: AuditLog | None = None,
        max_iters: int = 5,
    ) -> None:
        self.dispatcher = dispatcher
        self.guard = guard
        self.registry = registry
        self.client = client or LLMClient()
        self.cag = cag
        self.approval = approval
        self.audit = audit
        self.max_iters = max_iters
        # deterministic fallback path reuses the plain recon agent
        self._fallback = ReconAgent(dispatcher, guard, RuleBasedPlanner(), approval, audit)
        #: record of each LLM decision (for observability / demos)
        self.decisions: list[dict] = []

    async def run(self, target: str, name: str = "recon") -> Session:
        t: Target = self.guard.check(target)  # scope — raises if out of scope
        if self.audit:
            self.audit.scope_allow(target, actor="agentic-orchestrator")

        # if the very first decision can't be made, fall back deterministically
        try:
            first = self._decide(target, executed=[], last_results="")
        except LLMError:
            return await self._fallback.run(target, name=name)

        session = Session(name=name, mode=Mode.AUTO, targets=[t])
        executed: list[str] = []
        decision = first
        self.decisions = [first]
        layer = 0

        for _ in range(self.max_iters):
            jobs = self._jobs_from_decision(decision, target, session, executed, layer)
            layer += 1
            if jobs:
                results, digest = await self.dispatcher.run_batch(jobs)
                session.tool_results.extend(results)
                for r in results:
                    if r.status is ToolStatus.SUCCESS:
                        executed.append(r.tool)
                    session.findings.extend(findings_from_result(r))
            else:
                digest = ""

            if decision.get("done") or (not jobs and not decision.get("tools")):
                break
            try:
                decision = self._decide(target, executed, digest)
                self.decisions.append(decision)
            except LLMError:
                break

        session.touch()
        return session

    # -- internals ------------------------------------------------------

    def _decide(self, target: str, executed: list[str], last_results: str) -> dict:
        kind = ScopeGuard.classify(target).kind.value
        tools = [{"name": t.name, "category": t.category, "passive": t.passive}
                 for t in self.registry.all()]
        raw = self.client.complete(
            ORCHESTRATOR_SYSTEM,
            orchestrator_user(target, kind, tools, executed, last_results),
            role=Role.REASONING,
        )
        data = json.loads(_json(raw))
        if not isinstance(data, dict):
            raise LLMError("orchestrator returned non-object")
        return data

    def _jobs_from_decision(self, decision: dict, target: str, session: Session,
                            executed: list[str], layer: int) -> list[Job]:
        jobs: list[Job] = []
        for item in decision.get("tools", []) or []:
            name = (item or {}).get("tool")
            if not name:
                continue
            try:
                tool = self.registry.get(name)  # rejects unknown/dangerous tools
            except KeyError:
                continue
            task = Task(layer=f"{layer}", title=f"{name} {target}", assigned_tool=name)
            if not tool.passive:
                approved = self.approval(name, target)
                if self.audit:
                    self.audit.approval(name, target, "approved" if approved else "denied")
                if not approved:
                    task.status = TaskStatus.NA
                    task.notes = "denied at approval gate"
                    session.tasks.append(task)
                    continue
            task.status = TaskStatus.DONE
            session.tasks.append(task)
            jobs.append(Job(name, target, opts=_clean_opts(name, (item or {}).get("opts") or {})))
        return jobs


def _json(text: str) -> str:
    m = re.search(r"\{.*\}", text.strip(), re.DOTALL)
    return m.group(0) if m else text
