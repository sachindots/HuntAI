"""Textual TUI over the shared core engine.

Requires the `tui` extra (`pip install -e ".[tui]"`). Kept import-light so the
rest of HuntAI runs without Textual. Launch: `python -m huntai.tui.app`.
"""

from __future__ import annotations


from ..core import build_engine
from ..engine import FakeRunner


def _fake_engine():
    # offline demo runner; real runs use build_engine() with the sandbox
    from pathlib import Path
    root = Path(__file__).resolve().parents[3]
    fix = root / "tests" / "fixtures"
    fixtures = {n: (fix / f"{n}.{'xml' if n == 'nmap' else 'jsonl'}").read_text(encoding="utf-8")
                for n in ("nmap", "naabu", "httpx", "nuclei", "subfinder") if (fix / f"{n}.{'xml' if n=='nmap' else 'jsonl'}").exists()}
    return build_engine(runner=FakeRunner(fixtures))


def main() -> None:
    try:
        from textual.app import App, ComposeResult
        from textual.widgets import Footer, Header, Input, Log
    except ImportError:
        print("Textual not installed. Run: pip install -e \".[tui]\"")
        return

    engine = build_engine()

    class HuntAITUI(App):
        TITLE = "HuntAI"
        BINDINGS = [("q", "quit", "Quit")]

        def compose(self) -> ComposeResult:
            yield Header()
            yield Input(placeholder="lab target (e.g. 172.20.0.10)", id="target")
            yield Log(id="out")
            yield Footer()

        async def on_input_submitted(self, event: Input.Submitted) -> None:
            log = self.query_one("#out", Log)
            log.write_line(f"› assessing {event.value} …")
            try:
                session = await engine.orchestrator.run_auto(event.value)
            except Exception as exc:  # scope errors etc.
                log.write_line(f"✗ {exc}")
                return
            for f in session.findings:
                log.write_line(f"  [{f.severity.value.upper()}] {f.title}")
            log.write_line(f"✓ done — {len(session.findings)} finding(s)")

    HuntAITUI().run()


if __name__ == "__main__":
    main()
