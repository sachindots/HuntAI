"""ProjectDiscovery tools — all emit JSONL (one JSON object per line).

subfinder (passive subdomain), naabu (port scan), httpx (http probe),
nuclei (template vuln scan). Each parser is small and typed.
"""

from __future__ import annotations

import json

from ..schemas import ToolResult
from .base import Tool


def _jsonl(raw: str) -> list[dict]:
    out = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


class Subfinder(Tool):
    name = "subfinder"
    category = "subdomain"
    passive = True

    def build_argv(self, target: str, **opts) -> list[str]:
        return ["subfinder", "-d", target, "-silent", "-json"]

    def parse(self, raw: str, target: str) -> ToolResult:
        rows = _jsonl(raw)
        subs = sorted({r.get("host") for r in rows if r.get("host")})
        summary = f"subfinder {target}: {len(subs)} subdomain(s)."
        return self._result(target, {"subdomains": subs}, summary, self.build_argv(target))


class Naabu(Tool):
    name = "naabu"
    category = "port-scan"
    passive = False

    def build_argv(self, target: str, top_ports: int = 100, **opts) -> list[str]:
        return ["naabu", "-host", target, "-top-ports", str(top_ports), "-json", "-silent"]

    def parse(self, raw: str, target: str) -> ToolResult:
        rows = _jsonl(raw)
        ports = sorted({r["port"] for r in rows if "port" in r})
        summary = f"naabu {target}: open ports {ports}"
        return self._result(target, {"ports": ports}, summary, self.build_argv(target))


class Httpx(Tool):
    name = "httpx"
    category = "http-probe"
    passive = False

    def build_argv(self, target: str, **opts) -> list[str]:
        return ["httpx", "-u", target, "-json", "-silent", "-title", "-tech-detect", "-status-code"]

    def parse(self, raw: str, target: str) -> ToolResult:
        rows = _jsonl(raw)
        services = [{
            "url": r.get("url"),
            "status": r.get("status_code"),
            "title": r.get("title"),
            "tech": r.get("tech") or r.get("technologies") or [],
        } for r in rows]
        techs = sorted({t for s in services for t in s["tech"]})
        summary = f"httpx {target}: {len(services)} live http endpoint(s); tech={techs}"
        return self._result(target, {"services": services, "tech": techs},
                            summary, self.build_argv(target))


class Nuclei(Tool):
    name = "nuclei"
    category = "vuln-scan"
    passive = False

    def build_argv(self, target: str, severity: str | None = None, **opts) -> list[str]:
        # jsonl output; rate-limited + timed so we never hammer a live host
        argv = ["nuclei", "-u", target, "-jsonl", "-silent",
                "-rate-limit", "40", "-timeout", "8", "-no-color"]
        # default to actionable severities (skip info noise) unless overridden
        argv += ["-severity", severity or "low,medium,high,critical"]
        return argv

    def parse(self, raw: str, target: str) -> ToolResult:
        rows = _jsonl(raw)
        vulns = [{
            "template": r.get("template-id") or r.get("templateID"),
            "name": (r.get("info") or {}).get("name"),
            "severity": (r.get("info") or {}).get("severity", "info"),
            "matched": r.get("matched-at") or r.get("matched"),
        } for r in rows]
        by_sev: dict[str, int] = {}
        for v in vulns:
            by_sev[v["severity"]] = by_sev.get(v["severity"], 0) + 1
        summary = f"nuclei {target}: {len(vulns)} match(es) {by_sev}"
        return self._result(target, {"vulns": vulns, "by_severity": by_sev},
                            summary, self.build_argv(target))
