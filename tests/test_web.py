"""Web API tests — FastAPI over a fake-runner engine (offline)."""

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from huntai.core import build_engine
from huntai.engine import FakeRunner
from huntai.web import create_app

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def _fixtures():
    return {n: (FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
            for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder")}


@pytest.fixture
def client() -> TestClient:
    engine = build_engine(runner=FakeRunner(_fixtures()))
    return TestClient(create_app(engine))


def test_health(client):
    assert client.get("/api/health").json()["status"] == "ok"


def test_labs(client):
    names = {lab["name"] for lab in client.get("/api/labs").json()}
    assert {"dvwa", "juiceshop"} <= names


def test_assess_and_report_and_graph(client):
    r = client.post("/api/assess", json={"target": "172.20.0.10"}).json()
    assert r["total_findings"] > 0
    sid = r["session"]

    rep = client.get(f"/api/report/{sid}").json()
    assert rep["session"] == sid

    g = client.get(f"/api/graph/{sid}").json()
    assert g["mermaid"].startswith("graph TD")


def test_assess_out_of_scope(client):
    r = client.post("/api/assess", json={"target": "8.8.8.8"}).json()
    assert r["error"] == "out_of_scope"


def test_copilot(client):
    r = client.post("/api/copilot", json={"observation": "80/tcp open apache php"}).json()
    assert "httpx" in r["next_tools"]


def test_ws_assess_stream(client):
    with client.websocket_connect("/api/ws/assess") as ws:
        ws.send_json({"target": "172.20.0.10"})
        events = []
        while True:
            msg = ws.receive_json()
            events.append(msg["event"])
            if msg["event"] in ("done", "error"):
                break
    assert "start" in events and "task" in events and "done" in events
