"""Core typed models shared across every HuntAI component.

Everything that crosses an agent/tool/UI boundary is a Pydantic model so
outputs are structured (never scraped from free text) and validated once.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return uuid4().hex[:12]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    DONE = "done"
    NA = "not_applicable"


class ToolStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"


class Mode(str, Enum):
    AUTO = "auto"        # HuntAI drives, human approves active scans
    COPILOT = "copilot"  # user drives, HuntAI suggests on the side


class TargetKind(str, Enum):
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"
    URL = "url"


class Target(BaseModel):
    """A single in-scope thing to assess. Scope is enforced elsewhere."""

    raw: str
    kind: TargetKind
    label: str | None = None


class ToolResult(BaseModel):
    """Structured output of one tool run. `parsed` holds the tool-specific
    Pydantic payload serialized to dict; `summary` is the compacted form fed
    back to the LLM (raw stdout is NOT re-sent — token control)."""

    id: str = Field(default_factory=_new_id)
    tool: str
    args: list[str] = Field(default_factory=list)
    target: str
    status: ToolStatus = ToolStatus.QUEUED
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    parsed: dict = Field(default_factory=dict)
    summary: str = ""
    raw_ref: str | None = None  # path to raw output on disk, not inlined
    error: str | None = None


class Finding(BaseModel):
    """A single security-relevant observation."""

    id: str = Field(default_factory=_new_id)
    title: str
    severity: Severity = Severity.INFO
    target: str
    description: str = ""
    evidence: str = ""
    source_tool: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)  # e.g. ["T1595"]
    cve_ids: list[str] = Field(default_factory=list)
    remediation: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    validated: bool = False
    created_at: datetime = Field(default_factory=_utcnow)


class Task(BaseModel):
    """Node in the orchestrator's task tree. Layered ids like 1, 1.1, 1.1.1."""

    id: str = Field(default_factory=_new_id)
    layer: str = "1"
    title: str
    status: TaskStatus = TaskStatus.TODO
    parent: str | None = None
    children: list[str] = Field(default_factory=list)
    assigned_tool: str | None = None
    notes: str = ""


class Session(BaseModel):
    """Full persisted state of one assessment — resumable across runs."""

    id: str = Field(default_factory=_new_id)
    name: str = "untitled"
    mode: Mode = Mode.AUTO
    targets: list[Target] = Field(default_factory=list)
    tasks: list[Task] = Field(default_factory=list)
    tool_results: list[ToolResult] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def touch(self) -> None:
        self.updated_at = _utcnow()
