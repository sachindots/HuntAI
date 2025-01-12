"""Tool runners — where raw tool output actually comes from.

SandboxRunner executes inside the Docker `tools` container (never on host).
FakeRunner replays fixtures for tests / offline dev. Both are async so the
dispatcher can run many tools concurrently without blocking.
"""

from __future__ import annotations

import asyncio
from typing import Protocol

from ..tools.base import Tool


class ToolRunner(Protocol):
    async def run(self, tool: Tool, target: str, **opts) -> str:
        """Return raw tool output (stdout)."""
        ...


class SandboxRunner:
    """Runs a tool inside the docker compose `tools` service."""

    def __init__(self, compose_file: str, service: str = "tools") -> None:
        self.compose_file = compose_file
        self.service = service

    async def run(self, tool: Tool, target: str, **opts) -> str:
        argv = tool.build_argv(target, **opts)
        cmd = ["docker", "compose", "-f", self.compose_file,
               "exec", "-T", self.service, *argv]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        out, err = await proc.communicate()
        if proc.returncode not in (0, None):
            raise RuntimeError(f"{tool.name} failed: {err.decode(errors='ignore')[:200]}")
        return out.decode(errors="ignore")


class NativeRunner:
    """Runs a tool directly on the host via subprocess.

    Intended for running HuntAI ON a pentest distro (Kali/Parrot) where the
    tools are installed natively, without Docker. Scope + approval are still
    enforced upstream by the agent before a job ever reaches here.
    """

    def __init__(self, timeout: int = 900) -> None:
        self.timeout = timeout

    async def run(self, tool: Tool, target: str, **opts) -> str:
        argv = tool.build_argv(target, **opts)
        proc = await asyncio.create_subprocess_exec(
            *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"{tool.name} timed out after {self.timeout}s")
        if proc.returncode not in (0, None):
            msg = err.decode(errors="ignore")[:200]
            # nmap/nuclei sometimes exit non-zero with usable stdout; keep output if present
            if not out:
                raise RuntimeError(f"{tool.name} failed (rc={proc.returncode}): {msg}")
        return out.decode(errors="ignore")


class FakeRunner:
    """Replays canned raw output keyed by tool name. For tests/offline."""

    def __init__(self, fixtures: dict[str, str], delay: float = 0.0) -> None:
        self.fixtures = fixtures
        self.delay = delay

    async def run(self, tool: Tool, target: str, **opts) -> str:
        if self.delay:
            await asyncio.sleep(self.delay)
        if tool.name not in self.fixtures:
            raise KeyError(f"no fixture for tool {tool.name!r}")
        return self.fixtures[tool.name]
