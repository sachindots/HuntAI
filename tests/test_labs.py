"""Lab generator tests — no Docker required (subprocess mocked)."""

from pathlib import Path

import pytest

from huntai.labs import LabError, LabManager
from huntai.scope import ScopeGuard

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docker" / "labs.yaml"
COMPOSE = ROOT / "docker" / "docker-compose.yml"


@pytest.fixture
def guard() -> ScopeGuard:
    return ScopeGuard.from_yaml(ROOT / "scope.yaml")


@pytest.fixture
def mgr(guard) -> LabManager:
    return LabManager(REGISTRY, COMPOSE, guard)


def test_registry_loads(mgr):
    names = {lab.name for lab in mgr.list()}
    assert {"dvwa", "juiceshop"} <= names


def test_every_lab_ip_in_scope(mgr, guard):
    # the core safety invariant: generated targets are always in scope
    for lab in mgr.list():
        assert guard.is_in_scope(lab.ip)


def test_lab_url(mgr):
    dvwa = mgr.get("dvwa")
    assert dvwa.url == "http://172.20.0.10:80"


def test_out_of_scope_lab_rejected(tmp_path, guard):
    bad = tmp_path / "labs.yaml"
    bad.write_text(
        "labs:\n  evil:\n    profile: evil\n    ip: 8.8.8.8\n    port: 80\n",
        encoding="utf-8",
    )
    with pytest.raises(LabError):
        LabManager(bad, COMPOSE, guard)


def test_compose_command_shape(mgr):
    cmd = mgr._compose("up", "-d", profile="dvwa")
    assert cmd[:2] == ["docker", "compose"]
    assert "--profile" in cmd and "dvwa" in cmd
    assert "up" in cmd and "-d" in cmd


def test_up_requires_docker(monkeypatch, mgr):
    monkeypatch.setattr(LabManager, "_docker_available", staticmethod(lambda: False))
    with pytest.raises(LabError, match="Docker not found"):
        mgr.up("dvwa")


def test_up_success_path(monkeypatch, mgr):
    calls = {}

    class FakeProc:
        returncode = 0
        stdout = ""
        stderr = ""

    monkeypatch.setattr(LabManager, "_docker_available", staticmethod(lambda: True))

    def fake_run(self, cmd):
        calls["cmd"] = cmd
        return FakeProc()

    monkeypatch.setattr(LabManager, "_run", fake_run)
    lab = mgr.up("dvwa")
    assert lab.name == "dvwa"
    assert "--profile" in calls["cmd"] and "dvwa" in calls["cmd"]


def test_unknown_lab(mgr):
    with pytest.raises(LabError, match="unknown lab"):
        mgr.get("nope")
