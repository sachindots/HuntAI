"""Human-in-loop approval gate.

Active (packet-touching) tools must be approved before they run. The gate is a
callback so the CLI/web can prompt a human; tests inject auto/deny. Every
decision is auditable by the caller.
"""

from __future__ import annotations

from typing import Callable

# (tool_name, target) -> approved?
ApprovalGate = Callable[[str, str], bool]


def auto_approve(tool: str, target: str) -> bool:
    return True


def deny_all(tool: str, target: str) -> bool:
    return False


def approve_only(*tools: str) -> ApprovalGate:
    allowed = set(tools)
    return lambda tool, target: tool in allowed
