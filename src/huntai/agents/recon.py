"""ReconAgent — Auto mode.

Flow: scope-check the target → plan → run passive steps freely → gate every
active step through human approval → dispatch concurrently → fold results and
findings into the Session. Nothing touches a target that fails scope or is
denied at the gate.
"""

from __future__ import annotations

from ..audit import AuditLog
from ..engine.dispatcher import Dispatcher, Job
from ..schemas import Finding, Mode, Session, Severity, Target, Task, TaskStatus, ToolStatus
from ..scope import ScopeGuard
from .approval import ApprovalGate, auto_approve
from .planner import Planner, RuleBasedPlanner


def findings_from_result(result) -> list[Finding]:
    """Lightweight finding extraction. Deep MITRE/CVE enrichment = Phase 7."""
    out: list[Finding] = []
    if result.status is not ToolStatus.SUCCESS:
        return out
    p = result.parsed
    if result.tool == "nuclei":
        sev_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                   "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
        for v in p.get("vulns", []):
            out.append(Finding(
                title=v.get("name") or v.get("template") or "nuclei match",
                severity=sev_map.get(v.get("severity", "info"), Severity.INFO),
                target=result.target, source_tool="nuclei",
                evidence=str(v.get("matched") or ""),
            ))
    elif result.tool == "nmap":
        for h in p.get("hosts", []):
            for port in h.get("ports", []):
                out.append(Finding(
                    title=f"open {port['port']}/{port['protocol']} {port.get('service') or ''}".strip(),
                    severity=Severity.INFO, target=result.target, source_tool="nmap",
                    evidence=f"{port.get('product') or ''} {port.get('version') or ''}".strip(),
                ))
    return out


class ReconAgent:
    def __init__(
        self,
        dispatcher: Dispatcher,
        guard: ScopeGuard,
        planner: Planner | None = None,
        approval: ApprovalGate = auto_approve,
        audit: AuditLog | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.guard = guard
        self.planner = planner or RuleBasedPlanner()
        self.approval = approval
        self.audit = audit

    async def run(self, target: str, name: str = "recon") -> Session:
        # 1. scope — raises ScopeError if out of scope; caller must handle
        t: Target = self.guard.check(target)
        if self.audit:
            self.audit.scope_allow(target, actor="recon-agent")

        session = Session(name=name, mode=Mode.AUTO, targets=[t])

        # 2. plan → jobs, applying the approval gate to active steps
        jobs: list[Job] = []
        for i, step in enumerate(self.planner.plan(target), start=1):
            task = Task(layer=str(i), title=f"{step.tool} {step.target}",
                        assigned_tool=step.tool)
            if not step.passive:
                approved = self.approval(step.tool, step.target)
                if self.audit:
                    self.audit.approval(step.tool, step.target,
                                        "approved" if approved else "denied")
                if not approved:
                    task.status = TaskStatus.NA
                    task.notes = "denied at approval gate"
                    session.tasks.append(task)
                    continue
            task.status = TaskStatus.IN_PROGRESS
            session.tasks.append(task)
            jobs.append(Job(step.tool, step.target, opts=step.opts))

        # 3. dispatch concurrently, collect compacted results
        results, _digest = await self.dispatcher.run_batch(jobs)
        session.tool_results.extend(results)

        # 4. mark tasks + extract findings
        done_tools = {r.tool for r in results if r.status is ToolStatus.SUCCESS}
        for task in session.tasks:
            if task.status is TaskStatus.IN_PROGRESS:
                task.status = TaskStatus.DONE if task.assigned_tool in done_tools else TaskStatus.BLOCKED
        for r in results:
            session.findings.extend(findings_from_result(r))

        session.touch()
        return session
