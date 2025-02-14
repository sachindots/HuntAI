"""Analysis intelligence — MITRE ATT&CK mapping, CVE correlation, attack graph.

Turns raw recon findings into contextualized intelligence: technique labels,
known-CVE matches, and a graph of the target's exposure.
"""

from .cve import CVECorrelator
from .graph import AttackGraph, build_graph
from .intelligence import IntelligenceAgent
from .mitre import map_techniques

__all__ = ["IntelligenceAgent", "CVECorrelator", "map_techniques",
           "AttackGraph", "build_graph"]
