"""Tool base class.

A Tool knows how to (1) build its argv for the sandbox and (2) parse its
native output into a typed `ToolResult`. `passive=True` tools need no approval;
active tools touch the target and require the human-in-loop gate.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..schemas import ToolResult, ToolStatus


class Tool(ABC):
    name: str = ""
    category: str = ""
    passive: bool = False  # passive = OSINT, no packets at target
    #: output format the sandbox should request (informational)
    output: str = "json"

    @abstractmethod
    def build_argv(self, target: str, **opts) -> list[str]:
        """Return the command + args to run inside the sandbox."""

    @abstractmethod
    def parse(self, raw: str, target: str) -> ToolResult:
        """Parse raw tool output into a structured ToolResult."""

    # helper for subclasses
    def _result(self, target: str, parsed: dict, summary: str, argv: list[str]) -> ToolResult:
        return ToolResult(
            tool=self.name,
            args=argv,
            target=target,
            status=ToolStatus.SUCCESS,
            parsed=parsed,
            summary=summary,
        )
