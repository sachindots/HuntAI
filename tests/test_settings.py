"""Settings store + in-app scope authorization tests."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from huntai.core import build_engine
from huntai.core.settings_store import SettingsStore
from huntai.engine import FakeRunner
from huntai.scope import ScopeGuard
from huntai.web import create_app

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


# -- store --------------------------------------------------------------

def test_store_roundtrip_and_mask(tmp_path):
    s = SettingsStore(tmp_path / "settings.json")
    s.update({"nvidia_api_key": "nvapi-secret1234", "ollama_host": "http://h:1"})
    masked = s.masked()
    assert masked["ollama_host"] == "http://h:1"
    assert "secret" not in masked["nvidia_api_key"]  # masked
    assert masked["nvidia_api_key"].endswith("1234")


def test_store_ignores_unknown_keys(tmp_path):
    s = SettingsStore(tmp_path / "settings.json")
    s.update({"evil": "x", "prefer_offline": True})
    assert "evil" not in s.load()
    assert s.load()["prefer_offline"] is True


def test_authorized_target_requires_ack(tmp_path):
    s = SettingsStore(tmp_path / "settings.json")
    with pytest.raises(PermissionError):
        s.add_authorized_target("203.0.113.5", authorized=False)
    s.add_authorized_target("203.0.113.5", authorized=True)
    assert "203.0.113.5" in s.authorized_targets()


def test_scope_guard_add_allowed_permits_public():
    g = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    assert not g.is_in_scope("203.0.113.9")   # public, blocked by default
    g.add_allowed("203.0.113.9")
    assert g.is_in_scope("203.0.113.9")        # now authorized


def test_scope_guard_add_allowed_still_denies_metadata():
    g = ScopeGuard.from_yaml(ROOT / "scope.yaml")
    g.add_allowed("169.254.0.0/16")            # try to authorize metadata range
    assert not g.is_in_scope("169.254.169.254")  # explicit deny still wins


# -- web ----------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    # isolate the store to a temp file
    import huntai.web.app as appmod
    monkeypatch.setattr(appmod, "ROOT", tmp_path)
    engine = build_engine(runner=FakeRunner(_fixtures()))
    return TestClient(create_app(engine))


def test_settings_endpoint_masks(client):
    client.post("/api/settings", json={"nvidia_api_key": "nvapi-abcd1234"})
    got = client.get("/api/settings").json()
    assert got["nvidia_api_key"].endswith("1234")
    assert "abcd1234" not in got["nvidia_api_key"] or got["nvidia_api_key"].startswith("set")


def test_scope_endpoint_requires_ack(client):
    r = client.post("/api/scope", json={"target": "203.0.113.20", "authorized": False}).json()
    assert r["error"] == "authorization_required"
    r2 = client.post("/api/scope", json={"target": "203.0.113.20", "authorized": True}).json()
    assert "203.0.113.20" in r2["authorized_targets"]
