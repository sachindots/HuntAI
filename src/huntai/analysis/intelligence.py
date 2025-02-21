"""IntelligenceAgent — bundles MITRE mapping, CVE correlation, attack graph.

One `enrich(session)` call the Orchestrator drops in after analysis.
"""

from __future__ import annotations

from ..schemas import Session
from .cve import CVECorrelator
from .graph import AttackGraph, build_graph
from .mitre import map_techniques


class IntelligenceAgent:
    def __init__(self, cve: CVECorrelator | None = None) -> None:
        self.cve = cve or CVECorrelator()

    def enrich(self, session: Session) -> Session:
        self.cve.enrich(session)
        for f in session.findings:
            techs = map_techniques(f)
            if techs:
                f.mitre_techniques = sorted(set(f.mitre_techniques) | set(techs))
        session.touch()
        return session

    def graph(self, session: Session) -> AttackGraph:
        return build_graph(session)
