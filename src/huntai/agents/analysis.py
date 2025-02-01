"""AnalysisAgent — turns raw tool results into a deduplicated finding set.

Deep MITRE/CVE enrichment lives in `huntai.analysis` (Phase 7); this agent is
the orchestration seam that normalizes and merges findings across tools.
"""

from __future__ import annotations

from ..schemas import Finding, Session
from .recon import findings_from_result


class AnalysisAgent:
    def analyze(self, session: Session) -> Session:
        merged: dict[tuple[str, str], Finding] = {}
        # seed with any findings already on the session, then tool results
        seeds = list(session.findings)
        for r in session.tool_results:
            seeds.extend(findings_from_result(r))

        for f in seeds:
            key = (f.title.lower(), f.target)
            if key in merged:
                existing = merged[key]
                # keep the higher severity; remember corroborating tools
                srcs = set(filter(None, [existing.source_tool, f.source_tool]))
                existing.description = (existing.description or "") + \
                    (f" corroborated_by={sorted(srcs)}" if len(srcs) > 1 else "")
                if _sev_rank(f.severity) > _sev_rank(existing.severity):
                    existing.severity = f.severity
            else:
                merged[key] = f.model_copy(deep=True)

        session.findings = list(merged.values())
        session.touch()
        return session


def _sev_rank(sev) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    return order.index(sev.value)
