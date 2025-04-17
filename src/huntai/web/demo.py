"""Offline demo server — the web app wired to a fake runner so the UI works
end-to-end WITHOUT Docker (replays fixtures). For local viewing only.

    uvicorn huntai.web.demo:demo_app --factory
"""

from __future__ import annotations

from pathlib import Path

from ..core import build_engine
from ..engine import FakeRunner
from .app import create_app

_ROOT = Path(__file__).resolve().parents[3]
_FIX = _ROOT / "tests" / "fixtures"


def _fixtures() -> dict[str, str]:
    out = {}
    for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder"):
        p = _FIX / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}"
        if p.exists():
            out[n] = p.read_text(encoding="utf-8")
    return out


def demo_app():
    return create_app(build_engine(runner=FakeRunner(_fixtures())))
