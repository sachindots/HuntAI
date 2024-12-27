"""nmap — port scan + service/version detection. Parses -oX XML."""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..schemas import ToolResult
from .base import Tool


class Nmap(Tool):
    name = "nmap"
    category = "port-scan"
    passive = False
    output = "xml"

    def build_argv(self, target: str, ports: str | None = None, **opts) -> list[str]:
        argv = ["nmap", "-sV", "-oX", "-"]
        if ports:
            argv += ["-p", ports]
        argv.append(target)
        return argv

    def parse(self, raw: str, target: str) -> ToolResult:
        root = ET.fromstring(raw)
        hosts = []
        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr") if addr_el is not None else target
            ports = []
            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                ports.append({
                    "port": int(port.get("portid")),
                    "protocol": port.get("protocol"),
                    "service": svc.get("name") if svc is not None else None,
                    "product": svc.get("product") if svc is not None else None,
                    "version": svc.get("version") if svc is not None else None,
                })
            hosts.append({"address": addr, "ports": ports})

        n_open = sum(len(h["ports"]) for h in hosts)
        lines = [f"{p['port']}/{p['protocol']} {p['service'] or '?'} "
                 f"{(p['product'] or '').strip()} {(p['version'] or '').strip()}".strip()
                 for h in hosts for p in h["ports"]]
        summary = f"nmap {target}: {n_open} open port(s). " + "; ".join(lines)
        return self._result(target, {"hosts": hosts, "open_ports": n_open},
                            summary, self.build_argv(target))
