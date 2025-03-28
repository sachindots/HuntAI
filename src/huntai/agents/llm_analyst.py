"""LLMAnalyst — LLM-authored remediation + executive summary.

Untrusted output is confined to free-text fields (remediation, risk note,
summary). The LLM never changes severity, tool selection, or scope, and any
error leaves the session untouched (templated report still works).
"""

from __future__ import annotations

import json
import re

from ..config import Role
from ..llm.client import LLMClient, LLMError
from ..schemas import Session
from .prompts import ANALYST_SYSTEM, SUMMARY_SYSTEM, analyst_user, summary_user


class LLMAnalyst:
    def __init__(self, client: LLMClient | None = None) -> None:
        self.client = client or LLMClient()

    def enrich(self, session: Session) -> Session:
        if not session.findings:
            return session
        payload = [{"id": f.id, "title": f.title, "severity": f.severity.value,
                    "cve_ids": f.cve_ids, "mitre_techniques": f.mitre_techniques}
                   for f in session.findings]
        try:
            raw = self.client.complete(ANALYST_SYSTEM, analyst_user(payload), role=Role.REASONING)
            data = json.loads(_json(raw)).get("findings", {})
        except (LLMError, ValueError, json.JSONDecodeError, KeyError, TypeError):
            return session  # keep tool-derived findings as-is

        by_id = {f.id: f for f in session.findings}
        for fid, info in (data or {}).items():
            f = by_id.get(fid)
            if not f or not isinstance(info, dict):
                continue
            if info.get("remediation"):
                f.remediation = str(info["remediation"])[:600]
            if info.get("risk"):
                f.description = (f.description + " " if f.description else "") + \
                    f"risk: {str(info['risk'])[:300]}"
        session.touch()
        return session

    def executive_summary(self, report: dict) -> str:
        try:
            return self.client.complete(SUMMARY_SYSTEM, summary_user(report),
                                        role=Role.REASONING).strip()
        except LLMError:
            # deterministic fallback
            sev = report["by_severity"]
            worst = next((k for k in ("critical", "high", "medium", "low", "info")
                          if sev.get(k)), "info")
            return (f"Assessment of {', '.join(report['targets'])} produced "
                    f"{report['total_findings']} finding(s); highest severity: {worst}.")


def _json(text: str) -> str:
    m = re.search(r"\{.*\}", text.strip(), re.DOTALL)
    return m.group(0) if m else text
