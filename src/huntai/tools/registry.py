"""Tool registry — lookup + passive/active partitioning."""

from __future__ import annotations

from .base import Tool
from .nmap import Nmap
from .pdtools import Httpx, Naabu, Nuclei, Subfinder


class ToolRegistry:
    def __init__(self, tools: list[Tool] | None = None) -> None:
        self._tools: dict[str, Tool] = {}
        for t in tools or []:
            self.register(t)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool:
        if name not in self._tools:
            raise KeyError(f"unknown tool {name!r}. known: {', '.join(self._tools)}")
        return self._tools[name]

    def all(self) -> list[Tool]:
        return list(self._tools.values())

    def passive(self) -> list[Tool]:
        return [t for t in self._tools.values() if t.passive]

    def active(self) -> list[Tool]:
        return [t for t in self._tools.values() if not t.passive]

    def by_category(self, category: str) -> list[Tool]:
        return [t for t in self._tools.values() if t.category == category]


def default_registry() -> ToolRegistry:
    return ToolRegistry([Subfinder(), Naabu(), Nmap(), Httpx(), Nuclei()])
