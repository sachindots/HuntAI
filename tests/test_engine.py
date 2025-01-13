"""Async engine tests — concurrency, callbacks, token discipline. No plugin
needed: we drive the event loop with asyncio.run()."""

import asyncio
import time
from pathlib import Path

from huntai.engine import Dispatcher, FakeRunner, Job, TokenBudget, compact_results, estimate_tokens
from huntai.schemas import ToolStatus
from huntai.tools import default_registry

FIX = Path(__file__).parent / "fixtures"


def _fixtures() -> dict[str, str]:
    return {
        "nmap": (FIX / "nmap.xml").read_text(encoding="utf-8"),
        "naabu": (FIX / "naabu.jsonl").read_text(encoding="utf-8"),
        "httpx": (FIX / "httpx.jsonl").read_text(encoding="utf-8"),
        "nuclei": (FIX / "nuclei.jsonl").read_text(encoding="utf-8"),
    }


def _dispatcher(delay: float = 0.0, budget=None) -> Dispatcher:
    return Dispatcher(FakeRunner(_fixtures(), delay=delay), default_registry(),
                      max_concurrency=4, budget=budget)


def test_batch_runs_and_parses():
    d = _dispatcher()
    jobs = [Job("nmap", "172.20.0.10"), Job("naabu", "172.20.0.10"),
            Job("httpx", "172.20.0.10")]
    results, digest = asyncio.run(d.run_batch(jobs))
    assert len(results) == 3
    assert all(r.status is ToolStatus.SUCCESS for r in results)
    assert "nmap" in digest and "httpx" in digest


def test_concurrency_is_parallel():
    # 4 jobs each sleeping 0.1s should finish well under 0.4s if concurrent
    d = _dispatcher(delay=0.1)
    jobs = [Job(t, "172.20.0.10") for t in ("nmap", "naabu", "httpx", "nuclei")]
    start = time.perf_counter()
    asyncio.run(d.run_batch(jobs))
    assert time.perf_counter() - start < 0.35


def test_callbacks_fire():
    d = _dispatcher()
    seen = []

    async def cb(result):
        seen.append(result.tool)

    jobs = [Job("nmap", "x", on_done=cb), Job("httpx", "x", on_done=cb)]
    asyncio.run(d.run_batch(jobs))
    assert set(seen) == {"nmap", "httpx"}


def test_tool_failure_isolated():
    d = _dispatcher()
    # subfinder has no fixture in FakeRunner -> should FAIL, not crash batch
    results, _ = asyncio.run(d.run_batch([Job("nmap", "x"), Job("subfinder", "x")]))
    by = {r.tool: r for r in results}
    assert by["nmap"].status is ToolStatus.SUCCESS
    assert by["subfinder"].status is ToolStatus.FAILED
    assert by["subfinder"].error


def test_budget_charges_summary_not_raw():
    budget = TokenBudget(limit=100_000)
    d = _dispatcher(budget=budget)
    raw_len = len(_fixtures()["nmap"])
    asyncio.run(d.run_batch([Job("nmap", "x")]))
    # charged tokens must reflect the short summary, far less than raw output
    assert 0 < budget.spent < estimate_tokens("x" * raw_len)


def test_compact_digest_has_no_raw():
    d = _dispatcher()
    results, digest = asyncio.run(d.run_batch([Job("nmap", "x")]))
    assert "<port" not in digest
    assert compact_results(results).startswith("- [nmap]")
