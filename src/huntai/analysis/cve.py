"""CVE correlation.

Matches nmap service product+version against a bundled offline CVE database
(swap for a full cached NVD mirror in production). Adds cve_ids to findings and
bumps severity when a known-vulnerable version is confirmed.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..schemas import Finding, Session, Severity, ToolStatus

_DB_PATH = Path(__file__).parent / "cve_db.json"


class CVECorrelator:
    def __init__(self, db_path: str | Path = _DB_PATH) -> None:
        self.db: dict[str, dict[str, list[str]]] = json.loads(
            Path(db_path).read_text(encoding="utf-8")
        )

    def lookup(self, product: str | None, version: str | None) -> list[str]:
        if not product or not version:
            return []
        product = product.lower().strip()
        for known, versions in self.db.items():
            if known in product or product in known:
                # exact, else prefix match on version
                if version in versions:
                    return versions[version]
                for v, cves in versions.items():
                    if version.startswith(v) or v.startswith(version):
                        return cves
        return []

    def enrich(self, session: Session) -> Session:
        """Correlate CVEs from nmap service/version data and attach to findings."""
        # index nmap-derived open ports for the session
        for r in session.tool_results:
            if r.tool != "nmap" or r.status is not ToolStatus.SUCCESS:
                continue
            for host in r.parsed.get("hosts", []):
                for port in host.get("ports", []):
                    cves = self.lookup(port.get("product"), port.get("version"))
                    if not cves:
                        continue
                    # attach to a matching finding or create one
                    match = self._find_port_finding(session, r.target, port["port"])
                    if match is None:
                        match = Finding(
                            title=f"{port.get('product')} {port.get('version')} on {port['port']}",
                            target=r.target, source_tool="nmap")
                        session.findings.append(match)
                    match.cve_ids = sorted(set(match.cve_ids) | set(cves))
                    if match.severity in (Severity.INFO, Severity.LOW):
                        match.severity = Severity.MEDIUM  # known CVEs => at least medium
        session.touch()
        return session

    @staticmethod
    def _find_port_finding(session: Session, target: str, port: int) -> Finding | None:
        for f in session.findings:
            if f.target == target and f.source_tool == "nmap" and str(port) in f.title:
                return f
        return None
