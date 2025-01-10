"""Async execution engine — detaches slow tools from the LLM turn.

The LLM emits tool calls and its turn ENDS; the Dispatcher runs tools in the
background (concurrently) and wakes the caller with compacted results only.
No wait-loop tokens, no raw output re-sent.
"""

from .compaction import TokenBudget, compact_results, estimate_tokens
from .dispatcher import Dispatcher, Job
from .runner import FakeRunner, NativeRunner, SandboxRunner, ToolRunner

__all__ = [
    "Dispatcher", "Job", "ToolRunner", "SandboxRunner", "NativeRunner", "FakeRunner",
    "compact_results", "estimate_tokens", "TokenBudget",
]
