"""Lab generator — provisions vulnerable Docker targets inside the scope-locked
lab net (172.20.0.0/16).

HuntAI red-teams ONLY targets it generates here. On load, every lab IP is
asserted to be inside the scope guard's allowed range, so a misconfigured
registry can never point recon at something out of scope.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml
from pydantic import BaseModel

from .scope import ScopeError, ScopeGuard


class Lab(BaseModel):
    name: str
    profile: str
    ip: str
    port: int
    scheme: str = "http"
    image: str = ""
    description: str = ""

    @property
    def target(self) -> str:
        return self.ip

    @property
    def url(self) -> str:
        return f"{self.scheme}://{self.ip}:{self.port}"


class LabError(Exception):
    pass


class LabManager:
    def __init__(
        self,
        registry_path: str | Path,
        compose_file: str | Path,
        guard: ScopeGuard,
    ) -> None:
        self.registry_path = Path(registry_path)
        self.compose_file = Path(compose_file)
        self.guard = guard
        self.labs: dict[str, Lab] = self._load()

    def _load(self) -> dict[str, Lab]:
        data = yaml.safe_load(self.registry_path.read_text(encoding="utf-8"))
        labs: dict[str, Lab] = {}
        for name, spec in (data.get("labs") or {}).items():
            lab = Lab(name=name, **spec)
            # HARD invariant: a generated target must be in scope.
            if not self.guard.is_in_scope(lab.ip):
                raise LabError(
                    f"Lab {name!r} ip {lab.ip} is OUT OF SCOPE — refusing to load."
                )
            labs[name] = lab
        return labs

    # -- introspection --------------------------------------------------

    def list(self) -> list[Lab]:
        return list(self.labs.values())

    def get(self, name: str) -> Lab:
        if name not in self.labs:
            raise LabError(f"unknown lab {name!r}. known: {', '.join(self.labs)}")
        return self.labs[name]

    # -- compose command building --------------------------------------

    @staticmethod
    def _docker_available() -> bool:
        return shutil.which("docker") is not None

    def _compose(self, *args: str, profile: str | None = None) -> list[str]:
        cmd = ["docker", "compose", "-f", str(self.compose_file)]
        if profile:
            cmd += ["--profile", profile]
        cmd += list(args)
        return cmd

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        if not self._docker_available():
            raise LabError(
                "Docker not found. Install Docker Desktop (Windows/WSL2) or "
                "Docker Engine (Ubuntu) to run labs."
            )
        return subprocess.run(cmd, capture_output=True, text=True, check=False)

    # -- lifecycle ------------------------------------------------------

    def up(self, name: str) -> Lab:
        lab = self.get(name)
        # re-check scope at run time — belt and suspenders.
        try:
            self.guard.check(lab.ip)
        except ScopeError as exc:
            raise LabError(f"refusing to start out-of-scope lab: {exc}") from exc
        result = self._run(self._compose("up", "-d", profile=lab.profile))
        if result.returncode != 0:
            raise LabError(f"docker compose up failed:\n{result.stderr.strip()}")
        return lab

    def down(self, name: str) -> None:
        lab = self.get(name)
        self._run(self._compose("down", profile=lab.profile))

    def down_all(self) -> None:
        self._run(self._compose("down"))

    def status(self) -> str:
        result = self._run(self._compose("ps"))
        return result.stdout
