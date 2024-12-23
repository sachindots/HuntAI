"""Typed tool layer — every tool parses native JSON/XML into structured
`ToolResult`, never scraping free text. Registry is MCP-ready (Phase 8 adds
the MCP server adapter around these same tools)."""

from .base import Tool
from .registry import ToolRegistry, default_registry

__all__ = ["Tool", "ToolRegistry", "default_registry"]
