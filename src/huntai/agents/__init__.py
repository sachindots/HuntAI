"""Agents — planning, approval, and the recon agent (Auto mode).

Phase 4 ships a single recon agent with a human-in-loop approval gate. Phase 6
adds the orchestrator + specialist subagents and Copilot mode on top.
"""

from .agentic import AgenticReconAgent
from .analysis import AnalysisAgent
from .approval import ApprovalGate, auto_approve, deny_all
from .copilot import CopilotAgent, Suggestion
from .orchestrator import Orchestrator
from .llm_analyst import LLMAnalyst
from .llm_planner import LLMPlanner
from .planner import Planner, ReconStep, RuleBasedPlanner
from .recon import ReconAgent
from .reporter import ReporterAgent
from .validation import ValidationAgent

__all__ = [
    "ReconAgent", "AgenticReconAgent", "Planner", "RuleBasedPlanner", "LLMPlanner", "ReconStep",
    "ApprovalGate", "auto_approve", "deny_all",
    "AnalysisAgent", "ValidationAgent", "ReporterAgent", "LLMAnalyst",
    "CopilotAgent", "Suggestion", "Orchestrator",
]
