"""ValidationAgent — anti-false-positive pass.

Cross-checks findings before they reach a report: corroboration by multiple
tools or high severity raises confidence and marks `validated`; low-confidence
info noise is retained but flagged, keeping a human-oversight-friendly filter
between raw output and the report.
"""

from __future__ import annotations

from ..schemas import Session, Severity


class ValidationAgent:
    def __init__(self, min_confidence: float = 0.4) -> None:
        self.min_confidence = min_confidence

    def validate(self, session: Session) -> Session:
        for f in session.findings:
            corroborated = "corroborated_by=" in (f.description or "")
            high = f.severity in (Severity.HIGH, Severity.CRITICAL)

            if high:
                f.confidence = max(f.confidence, 0.8)
                f.validated = True
            elif corroborated:
                f.confidence = max(f.confidence, 0.7)
                f.validated = True
            elif f.severity is Severity.INFO:
                f.confidence = min(f.confidence, 0.3)
                f.validated = False
            else:
                f.validated = f.confidence >= self.min_confidence

        session.touch()
        return session

    def report_worthy(self, session: Session):
        """Findings that pass the confidence floor — what a human reviews."""
        return [f for f in session.findings if f.confidence >= self.min_confidence]
