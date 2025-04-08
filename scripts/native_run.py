"""Run the REAL, LLM-driven pipeline with native tools (no Docker).

For use on a pentest distro (Kali/Parrot) where nmap/httpx/nuclei/etc. are
installed on the host. The LLM (NVIDIA NIM / Ollama) ORCHESTRATES: it decides
which tools to run, reads the results, and decides what to run next.

    python scripts/native_run.py <target>

LLM mode turns on automatically when a provider key is configured
(HUNTAI_NVIDIA_API_KEY) or Ollama is reachable; otherwise it falls back to a
deterministic plan. Scope guard still applies — authorize non-lab targets with
`huntai scope add <t> --yes`.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from huntai.analysis import build_graph  # noqa: E402
from huntai.config import Role, get_settings  # noqa: E402
from huntai.core import build_engine  # noqa: E402
from huntai.engine import NativeRunner  # noqa: E402
from huntai.schemas import ToolStatus  # noqa: E402
from huntai.scope import ScopeError  # noqa: E402


async def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    settings = get_settings()
    provider, model = settings.route(Role.REASONING)
    use_llm = bool(settings.nvidia_api_key) or bool(settings.gemini_api_key) or settings.prefer_offline

    print("=" * 64)
    print(f"  HuntAI — LLM-driven recon   target={target}")
    print(f"  orchestrator: {'LLM ' + provider.value + ':' + model if use_llm else 'rule-based (no LLM configured)'}")
    print("=" * 64)

    engine = build_engine(runner=NativeRunner(), use_llm=use_llm)
    try:
        session = await engine.orchestrator.run_auto(target)
    except ScopeError as exc:
        print(f"OUT OF SCOPE: {exc}")
        return 1

    recon = engine.orchestrator.recon
    decisions = getattr(recon, "decisions", [])
    if decisions:
        print("\nLLM ORCHESTRATION (each step decided from prior results):")
        for i, d in enumerate(decisions, 1):
            tools = [t.get("tool") for t in (d.get("tools") or [])]
            print(f"  step {i}: run {tools or '—'}  done={d.get('done')}")
            if d.get("rationale"):
                print(f"          reason: {d['rationale']}")

    print("\nTOOLS EXECUTED:")
    for r in session.tool_results:
        print(f"  {r.tool:10} {r.status.value:8} {r.summary or r.error or ''}")

    print(f"\nFINDINGS ({len(session.findings)}):")
    for f in sorted(session.findings, key=lambda x: x.severity.value):
        line = f"  [{f.severity.value.upper():8}] {f.title}"
        if f.cve_ids:
            line += f"  cve={','.join(f.cve_ids)}"
        if f.mitre_techniques:
            line += f"  mitre={','.join(f.mitre_techniques)}"
        print(line)
        if f.remediation:
            print(f"             fix: {f.remediation}")

    rep = engine.orchestrator.last_report
    print(f"\nSEVERITY: {rep['by_severity']}")
    if rep.get("executive_summary"):
        print(f"\nLLM SUMMARY: {rep['executive_summary']}")
    ran = [r.tool for r in session.tool_results if r.status is ToolStatus.SUCCESS]
    failed = [r.tool for r in session.tool_results if r.status is not ToolStatus.SUCCESS]
    print(f"\ntools ran: {ran}   failed: {failed or 'none'}")
    print("\nATTACK GRAPH:")
    print(build_graph(session).to_mermaid())
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
