"""Async dispatcher — non-blocking, concurrent tool execution.

Submit jobs and return immediately (the LLM turn is free to end). Jobs run
concurrently under a semaphore; each completion parses raw → ToolResult and
fires an optional callback. `run_batch` awaits a set of jobs and hands back one
compacted digest — the only thing the LLM ever sees.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

from ..schemas import ToolResult, ToolStatus
from ..tools.registry import ToolRegistry
from .compaction import TokenBudget, compact_results
from .runner import ToolRunner

OnDone = Callable[[ToolResult], Awaitable[None] | None]


@dataclass
class Job:
    tool: str
    target: str
    opts: dict = field(default_factory=dict)
    on_done: OnDone | None = None


class Dispatcher:
    def __init__(
        self,
        runner: ToolRunner,
        registry: ToolRegistry,
        max_concurrency: int = 4,
        budget: TokenBudget | None = None,
    ) -> None:
        self.runner = runner
        self.registry = registry
        self.sem = asyncio.Semaphore(max_concurrency)
        self.budget = budget or TokenBudget()

    async def _run_one(self, job: Job) -> ToolResult:
        tool = self.registry.get(job.tool)
        async with self.sem:
            started = datetime.now(timezone.utc)
            try:
                raw = await self.runner.run(tool, job.target, **job.opts)
                result = tool.parse(raw, job.target)
                # charge only the compact summary, never the raw output
                self.budget.charge(result.summary)
            except Exception as exc:  # tool crash must not kill the batch
                result = ToolResult(
                    tool=job.tool, target=job.target,
                    status=ToolStatus.FAILED, error=str(exc)[:300],
                    summary=f"{job.tool} failed: {str(exc)[:120]}",
                )
            result.started_at = started
            result.finished_at = datetime.now(timezone.utc)

        if job.on_done is not None:
            res = job.on_done(result)
            if asyncio.iscoroutine(res):
                await res
        return result

    async def run_batch(self, jobs: list[Job]) -> tuple[list[ToolResult], str]:
        """Run jobs concurrently; return (results, compacted digest)."""
        results = await asyncio.gather(*(self._run_one(j) for j in jobs))
        return list(results), compact_results(list(results))

    def submit_background(self, jobs: list[Job]) -> asyncio.Task:
        """Fire-and-return: caller's turn can end; results arrive via on_done."""
        return asyncio.ensure_future(self.run_batch(jobs))
