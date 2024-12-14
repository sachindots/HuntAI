"""Append-only audit log.

Every scope decision, approval, and tool execution is written as one JSON
line. This is the accountability trail — who approved what, when, against
which target. Never mutate or delete entries.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path = "./data/audit.log") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, event: str, **fields) -> None:
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **fields,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")

    # convenience wrappers for the common events
    def scope_allow(self, target: str, actor: str = "system") -> None:
        self.record("scope_allow", target=target, actor=actor)

    def scope_deny(self, target: str, reason: str, actor: str = "system") -> None:
        self.record("scope_deny", target=target, reason=reason, actor=actor)

    def approval(self, tool: str, target: str, decision: str, actor: str = "user") -> None:
        self.record("approval", tool=tool, target=target, decision=decision, actor=actor)

    def tool_run(self, tool: str, target: str, status: str, **extra) -> None:
        self.record("tool_run", tool=tool, target=target, status=status, **extra)
