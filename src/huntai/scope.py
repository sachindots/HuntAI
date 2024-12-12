"""Scope guard — the hard safety boundary.

Every target must pass `ScopeGuard.check()` before any tool touches it. This
is enforced in code, never left to the LLM. Default posture is lab-only:
public IPs are denied while `require_explicit_public` is true, and explicit
deny rules always beat allow rules.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path

import yaml

from .schemas import Target, TargetKind


class ScopeError(Exception):
    """Raised when a target is out of scope. Callers must not proceed."""


def _norm_domain(d: str) -> str:
    """Normalize an allow_domains entry to a bare hostname (accepts URLs too)."""
    d = d.strip().lower()
    if "://" in d:
        from urllib.parse import urlparse
        return (urlparse(d).hostname or d).lstrip("*")
    return d.split("/")[0].lstrip("*")


class ScopeGuard:
    def __init__(
        self,
        allow_cidrs: list[str],
        allow_domains: list[str],
        deny_cidrs: list[str],
        lab_net: str,
        mode: str = "lab",
        require_explicit_public: bool = True,
    ) -> None:
        self.mode = mode
        self.require_explicit_public = require_explicit_public
        self.allow_cidrs = [ipaddress.ip_network(c, strict=False) for c in allow_cidrs]
        self.deny_cidrs = [ipaddress.ip_network(c, strict=False) for c in deny_cidrs]
        self.lab_net = ipaddress.ip_network(lab_net, strict=False)
        self.allow_domains = [_norm_domain(d) for d in allow_domains]

    def add_allowed(self, target: str) -> None:
        """Extend scope with a user-authorized target (ip / cidr / domain / url).
        Deny rules still apply and are checked at enforcement time."""
        t = self.classify(target)
        if t.kind in (TargetKind.IP, TargetKind.CIDR):
            self.allow_cidrs.append(ipaddress.ip_network(t.raw, strict=False))
        elif t.kind == TargetKind.URL:
            from urllib.parse import urlparse
            host = urlparse(t.raw).hostname
            if host:
                self.allow_domains.append(_norm_domain(host))
        else:
            self.allow_domains.append(_norm_domain(t.raw))

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ScopeGuard":
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(
            allow_cidrs=data.get("allow_cidrs", []),
            allow_domains=data.get("allow_domains", []),
            deny_cidrs=data.get("deny_cidrs", []),
            lab_net=data["lab_net"],
            mode=data.get("mode", "lab"),
            require_explicit_public=data.get("require_explicit_public", True),
        )

    # -- classification -------------------------------------------------

    @staticmethod
    def classify(raw: str) -> Target:
        """Turn a raw target string into a typed Target."""
        s = raw.strip()
        if s.startswith(("http://", "https://")):
            return Target(raw=s, kind=TargetKind.URL)
        if "/" in s:
            try:
                ipaddress.ip_network(s, strict=False)
                return Target(raw=s, kind=TargetKind.CIDR)
            except ValueError:
                pass
        try:
            ipaddress.ip_address(s)
            return Target(raw=s, kind=TargetKind.IP)
        except ValueError:
            return Target(raw=s.lower(), kind=TargetKind.DOMAIN)

    # -- enforcement ----------------------------------------------------

    def _ip_allowed(self, ip: ipaddress._BaseAddress) -> bool:
        for net in self.deny_cidrs:
            if ip in net:
                raise ScopeError(f"{ip} is in an explicit deny range ({net}).")
        if ip in self.lab_net:
            return True
        for net in self.allow_cidrs:
            if ip in net:
                return True
        if self.require_explicit_public and getattr(ip, "is_global", False):
            raise ScopeError(f"{ip} is a public address; blocked by lab policy.")
        raise ScopeError(f"{ip} is not in any allowed range.")

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower()
        for d in self.allow_domains:
            if host == d or host.endswith(d if d.startswith(".") else f".{d}") or host == d.lstrip("."):
                return True
        raise ScopeError(f"Domain {host!r} not in allow_domains.")

    def check(self, raw: str) -> Target:
        """Return a validated Target or raise ScopeError. Never returns False."""
        target = self.classify(raw)

        if target.kind in (TargetKind.IP,):
            self._ip_allowed(ipaddress.ip_address(target.raw))
        elif target.kind == TargetKind.CIDR:
            net = ipaddress.ip_network(target.raw, strict=False)
            # require both endpoints in scope
            self._ip_allowed(net.network_address)
            self._ip_allowed(net.broadcast_address)
        elif target.kind == TargetKind.URL:
            from urllib.parse import urlparse

            host = urlparse(target.raw).hostname or ""
            try:
                self._ip_allowed(ipaddress.ip_address(host))
            except ValueError:
                self._domain_allowed(host)
        else:  # DOMAIN
            self._domain_allowed(target.raw)

        return target

    def is_in_scope(self, raw: str) -> bool:
        """Boolean convenience wrapper — swallows ScopeError."""
        try:
            self.check(raw)
            return True
        except ScopeError:
            return False
