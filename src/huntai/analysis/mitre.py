"""MITRE ATT&CK technique mapping.

Maps a finding to ATT&CK technique ids by source tool and title keywords.
Recon-heavy for now (TA0043 Reconnaissance), plus a few access techniques the
findings imply. Extendable via the tables below.
"""

from __future__ import annotations

from ..schemas import Finding

# source tool -> technique ids
_TOOL_TECHNIQUES: dict[str, list[str]] = {
    "subfinder": ["T1590.002"],   # Gather Victim Network Info: DNS
    "naabu": ["T1595.001"],       # Active Scanning: Scanning IP Blocks
    "nmap": ["T1595.001"],        # Active Scanning: Scanning IP Blocks
    "httpx": ["T1595.002"],       # Active Scanning: Vulnerability Scanning
    "nuclei": ["T1595.002"],      # Active Scanning: Vulnerability Scanning
}

# title keyword -> technique ids
_KEYWORD_TECHNIQUES: list[tuple[str, list[str]]] = [
    ("default login", ["T1078"]),        # Valid Accounts
    ("default credential", ["T1078"]),
    ("weak password", ["T1110"]),        # Brute Force
    ("ssh", ["T1021.004"]),              # Remote Services: SSH
    ("sql injection", ["T1190"]),        # Exploit Public-Facing Application
    ("xss", ["T1059.007"]),              # Command/Scripting: JavaScript
    ("exposed .git", ["T1213"]),         # Data from Information Repositories
]


def map_techniques(finding: Finding) -> list[str]:
    techs: list[str] = []
    if finding.source_tool in _TOOL_TECHNIQUES:
        techs += _TOOL_TECHNIQUES[finding.source_tool]
    title = finding.title.lower()
    for kw, ids in _KEYWORD_TECHNIQUES:
        if kw in title:
            techs += ids
    # de-dup, keep order
    seen: set[str] = set()
    return [t for t in techs if not (t in seen or seen.add(t))]
