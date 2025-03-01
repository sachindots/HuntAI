"""Single wiring point for the whole system.

Both the Textual CLI and the FastAPI web server call `build_engine()` so they
drive identical logic. Inject a runner (FakeRunner) for offline/test; default
is the Docker SandboxRunner.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..agents import (
    AgenticReconAgent,
    AnalysisAgent,
    CopilotAgent,
    LLMAnalyst,
    Orchestrator,
    ReconAgent,
    ReporterAgent,
    ValidationAgent,
)
from ..analysis import IntelligenceAgent
from ..config import get_settings
from ..engine import Dispatcher, NativeRunner, SandboxRunner
from ..engine.runner import ToolRunner
from ..kb import CAGStore, FindingsMemory
from ..llm import LLMClient
from ..scope import ScopeGuard
from ..tools import default_registry

ROOT = Path(__file__).resolve().parents[3]


@dataclass
class HuntAIEngine:
    guard: ScopeGuard
    orchestrator: Orchestrator
    cag: CAGStore
    memory: FindingsMemory


def load_guard() -> ScopeGuard:
    """Build the scope guard from scope.yaml + env HUNTAI_ALLOWED_TARGETS +
    targets authorized in-app. One place, so CLI and web agree on scope."""
    from .settings_store import SettingsStore
    guard = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    extra = list(get_settings().allowed_list())
    extra += SettingsStore(ROOT / "data" / "settings.json").authorized_targets()
    for tgt in extra:
        try:
            guard.add_allowed(tgt)
        except ValueError:
            continue
    return guard


def _default_runner() -> ToolRunner:
    """Native tools when HUNTAI_NATIVE_TOOLS is set (running on Kali/Parrot),
    otherwise the Docker sandbox."""
    if os.getenv("HUNTAI_NATIVE_TOOLS"):
        return NativeRunner()
    return SandboxRunner(str(ROOT / "docker" / "docker-compose.yml"))


def build_engine(
    runner: ToolRunner | None = None,
    use_llm: bool | None = None,
    approval=None,
) -> HuntAIEngine:
    settings = get_settings()
    # auto-enable LLM orchestration when a provider is configured
    if use_llm is None:
        use_llm = bool(settings.nvidia_api_key or settings.gemini_api_key
                       or settings.prefer_offline)

    guard = load_guard()
    registry = default_registry()
    if runner is None:
        runner = _default_runner()
    dispatcher = Dispatcher(runner, registry)

    cag = CAGStore(ROOT / "kb").load()
    memory = FindingsMemory()
    copilot = CopilotAgent(cag=cag, memory=memory)

    # LLM is opt-in; the agentic orchestrator + analyst fall back gracefully.
    from ..agents.approval import auto_approve
    gate = approval or auto_approve
    analyst: LLMAnalyst | None = None
    if use_llm:
        client = LLMClient()
        recon = AgenticReconAgent(dispatcher, guard, registry, client=client,
                                  cag=cag, approval=gate)
        analyst = LLMAnalyst(client=client)
    else:
        recon = ReconAgent(dispatcher, guard, approval=gate)

    orchestrator = Orchestrator(
        recon=recon,
        analysis=AnalysisAgent(),
        validation=ValidationAgent(),
        reporter=ReporterAgent(),
        copilot=copilot,
        intelligence=IntelligenceAgent(),
        llm_analyst=analyst,
    )
    return HuntAIEngine(guard=guard, orchestrator=orchestrator, cag=cag, memory=memory)
