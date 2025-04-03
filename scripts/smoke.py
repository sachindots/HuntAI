"""HuntAI preflight + live smoke test.

Checks the runtime prerequisites, then (if Docker is available) spins the DVWA
lab, runs one real assessment against it, prints the report, and tears the lab
down. Every check degrades gracefully — missing prereqs are reported, not fatal.

    python scripts/smoke.py            # preflight + live scan if possible
    python scripts/smoke.py --check    # preflight only
"""

from __future__ import annotations

import asyncio
import shutil
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

# make output safe on legacy Windows consoles (cp1252)
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console  # noqa: E402

from huntai.config import get_settings  # noqa: E402

console = Console()
ROOT = Path(__file__).resolve().parents[1]


# ASCII markers only — legacy Windows consoles (cp1252) can't encode glyphs.
def _ok(msg): console.print(f"[green]\\[OK][/] {msg}")
def _no(msg): console.print(f"[red]\\[X][/]  {msg}")
def _warn(msg): console.print(f"[yellow]\\[!][/]  {msg}")


def check_docker() -> bool:
    if not shutil.which("docker"):
        _no("docker not found — install Docker Desktop (Windows/WSL2) or Engine (Ubuntu)")
        return False
    import subprocess
    r = subprocess.run(["docker", "info"], capture_output=True, text=True)
    if r.returncode != 0:
        _no("docker installed but daemon not running — start Docker Desktop")
        return False
    _ok("docker running")
    return True


def check_ollama() -> bool:
    host = get_settings().ollama_host.rstrip("/")
    try:
        with urllib.request.urlopen(f"{host}/api/tags", timeout=2) as resp:
            if resp.status == 200:
                _ok(f"ollama reachable at {host}")
                return True
    except Exception:
        pass
    _warn(f"ollama not reachable at {host} — local models unavailable (install: ollama.com)")
    return False


def check_nvidia() -> bool:
    if get_settings().nvidia_api_key:
        _ok("NVIDIA NIM key present")
        return True
    _warn("no NVIDIA NIM key (HUNTAI_NVIDIA_API_KEY) — reasoning falls back to Ollama")
    return False


def check_openai() -> bool:
    try:
        import openai  # noqa: F401
        _ok("openai SDK installed (live LLM orchestration enabled)")
        return True
    except ImportError:
        _warn("openai SDK not installed — LLM orchestrator/analyst fall back to "
              "rule-based (pip install -e \".[llm]\")")
        return False


async def live_scan(use_llm: bool) -> None:
    from huntai.core import build_engine
    from huntai.labs import LabManager
    from huntai.scope import ScopeGuard

    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    mgr = LabManager(ROOT / "docker" / "labs.yaml",
                     ROOT / "docker" / "docker-compose.yml", guard)

    console.rule("[bold]live scan — DVWA lab")
    lab = mgr.up("dvwa")
    _ok(f"lab up: {lab.url}")
    try:
        time.sleep(5)  # let the container settle
        engine = build_engine(use_llm=use_llm)  # real SandboxRunner
        session = await engine.orchestrator.run_auto(lab.target, name="smoke")
        console.print(f"\n[bold]{len(session.findings)} finding(s):[/]")
        for f in session.findings:
            console.print(f"  [{f.severity.value.upper()}] {f.title} "
                          f"{f.cve_ids or ''} {f.mitre_techniques or ''}")
        if engine.orchestrator.last_report.get("executive_summary"):
            console.print(f"\n[italic]{engine.orchestrator.last_report['executive_summary']}[/]")
    finally:
        mgr.down("dvwa")
        _ok("lab down")


def main() -> int:
    console.rule("[bold cyan]HuntAI preflight")
    docker = check_docker()
    check_ollama()
    nim = check_nvidia()
    llm = check_openai()

    if "--check" in sys.argv:
        return 0
    if not docker:
        _warn("skipping live scan (needs Docker). Re-run after installing Docker.")
        return 0

    use_llm = llm and (nim or True)  # llm dep present -> try; falls back internally
    asyncio.run(live_scan(use_llm=use_llm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
