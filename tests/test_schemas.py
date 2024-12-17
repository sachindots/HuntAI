"""Schema + config-routing sanity tests."""

from huntai.config import Provider, Role, Settings
from huntai.schemas import (
    Finding,
    Session,
    Severity,
    Target,
    TargetKind,
    Task,
    TaskStatus,
    ToolResult,
    ToolStatus,
)


def test_session_roundtrip():
    s = Session(name="lab-run")
    s.targets.append(Target(raw="172.20.0.5", kind=TargetKind.IP))
    s.tasks.append(Task(layer="1", title="passive recon"))
    s.findings.append(Finding(title="open port 80", severity=Severity.LOW, target="172.20.0.5"))
    s.tool_results.append(ToolResult(tool="nmap", target="172.20.0.5", status=ToolStatus.SUCCESS))

    dumped = s.model_dump_json()
    loaded = Session.model_validate_json(dumped)
    assert loaded.name == "lab-run"
    assert loaded.findings[0].severity is Severity.LOW
    assert loaded.tasks[0].status is TaskStatus.TODO


def test_finding_confidence_bounds():
    f = Finding(title="x", target="t", confidence=0.9)
    assert 0.0 <= f.confidence <= 1.0


def test_routing_offline_forces_ollama():
    s = Settings(prefer_offline=True, nvidia_api_key="fake")
    assert s.route(Role.REASONING)[0] is Provider.OLLAMA


def test_routing_uses_nvidia_when_key_present():
    s = Settings(prefer_offline=False, nvidia_api_key="fake")
    assert s.route(Role.REASONING)[0] is Provider.NVIDIA


def test_routing_falls_back_without_key():
    s = Settings(prefer_offline=False, nvidia_api_key=None)
    assert s.route(Role.REASONING)[0] is Provider.OLLAMA


def test_parsing_always_local():
    s = Settings(nvidia_api_key="fake")
    assert s.route(Role.PARSING)[0] is Provider.OLLAMA
