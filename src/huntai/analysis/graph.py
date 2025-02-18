"""Attack graph — target → services → findings, exportable as Mermaid.

Pure-python (no networkx dep). Nodes and edges are derived from the session's
tool results and findings; `to_mermaid()` renders a diagram the web UI and
reports embed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..schemas import Session, Severity, ToolStatus

_SEV_STYLE = {
    Severity.CRITICAL: "fill:#7f1d1d,color:#fff",
    Severity.HIGH: "fill:#b91c1c,color:#fff",
    Severity.MEDIUM: "fill:#c2410c,color:#fff",
    Severity.LOW: "fill:#a16207,color:#fff",
    Severity.INFO: "fill:#334155,color:#fff",
}


@dataclass
class AttackGraph:
    nodes: dict[str, dict] = field(default_factory=dict)  # id -> {label, kind, sev?}
    edges: list[tuple[str, str]] = field(default_factory=list)

    def add_node(self, nid: str, label: str, kind: str, sev: Severity | None = None) -> None:
        self.nodes[nid] = {"label": label, "kind": kind, "sev": sev}

    def add_edge(self, a: str, b: str) -> None:
        if (a, b) not in self.edges:
            self.edges.append((a, b))

    def to_mermaid(self) -> str:
        lines = ["graph TD"]
        for nid, n in self.nodes.items():
            label = n["label"].replace('"', "'")
            lines.append(f'    {nid}["{label}"]')
        for a, b in self.edges:
            lines.append(f"    {a} --> {b}")
        for nid, n in self.nodes.items():
            if n.get("sev") is not None:
                lines.append(f"    style {nid} {_SEV_STYLE[n['sev']]}")
        return "\n".join(lines)


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in s)


def build_graph(session: Session) -> AttackGraph:
    g = AttackGraph()
    for t in session.targets:
        g.add_node(f"t_{_safe(t.raw)}", t.raw, "target")

    # service nodes from nmap
    for r in session.tool_results:
        if r.tool == "nmap" and r.status is ToolStatus.SUCCESS:
            for host in r.parsed.get("hosts", []):
                tnode = f"t_{_safe(r.target)}"
                if tnode not in g.nodes:
                    g.add_node(tnode, r.target, "target")
                for port in host.get("ports", []):
                    sid = f"s_{_safe(r.target)}_{port['port']}"
                    g.add_node(sid, f"{port['port']}/{port.get('service') or '?'}", "service")
                    g.add_edge(tnode, sid)

    # finding nodes
    for i, f in enumerate(session.findings):
        fid = f"f_{i}"
        g.add_node(fid, f"{f.severity.value.upper()}: {f.title}", "finding", sev=f.severity)
        # attach to its target (or a service node if port in title)
        tnode = f"t_{_safe(f.target)}"
        parent = tnode
        for nid, n in g.nodes.items():
            if n["kind"] == "service" and nid.startswith(f"s_{_safe(f.target)}_") \
                    and nid.rsplit("_", 1)[-1] in f.title:
                parent = nid
                break
        if tnode not in g.nodes:
            g.add_node(tnode, f.target, "target")
        g.add_edge(parent, fid)
    return g
