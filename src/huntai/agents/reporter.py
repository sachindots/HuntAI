"""ReporterAgent — structured assessment report from a Session.

Emits a typed dict (for the web/API) and a Markdown rendering (CLI/export).
HTML/PDF export builds on this in Phase 8.
"""

from __future__ import annotations

from ..schemas import Session, Severity

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ReporterAgent:
    def report(self, session: Session) -> dict:
        by_sev = {s.value: 0 for s in _SEV_ORDER}
        for f in session.findings:
            by_sev[f.severity.value] += 1
        findings = sorted(
            session.findings,
            key=lambda f: (_SEV_ORDER.index(f.severity), -f.confidence),
        )
        return {
            "session": session.id,
            "name": session.name,
            "mode": session.mode.value,
            "targets": [t.raw for t in session.targets],
            "by_severity": by_sev,
            "total_findings": len(session.findings),
            "findings": [f.model_dump() for f in findings],
            "tasks": [{"layer": t.layer, "title": t.title, "status": t.status.value}
                      for t in session.tasks],
        }

    def markdown(self, session: Session) -> str:
        rep = self.report(session)
        lines = [
            f"# HuntAI Report — {rep['name']}",
            f"Targets: {', '.join(rep['targets'])}  ·  Mode: {rep['mode']}",
            "",
            "## Severity summary",
        ]
        for sev, n in rep["by_severity"].items():
            if n:
                lines.append(f"- **{sev}**: {n}")
        lines += ["", "## Findings"]
        for f in rep["findings"]:
            mark = "✔" if f["validated"] else "?"
            lines.append(f"- [{mark}] **{f['severity'].upper()}** {f['title']} "
                         f"({f['target']}, conf {f['confidence']:.1f})")
            if f["evidence"]:
                lines.append(f"    - evidence: {f['evidence']}")
        return "\n".join(lines)
