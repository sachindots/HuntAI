"""Minimal CLI entrypoint (Phase 0).

Full Textual TUI arrives in Phase 8. For now this proves the wiring: load
scope, classify a target, report in/out of scope. No scanning happens here.
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

from .audit import AuditLog
from .config import get_settings
from .labs import LabError, LabManager
from .scope import ScopeError, ScopeGuard

console = Console()

USAGE = """[bold cyan]HuntAI[/] v0.2 — lab-scoped recon framework

usage:
  huntai check <target>        classify + scope-check a target
  huntai lab list              list available vuln labs
  huntai lab up <name>         start a lab target (scope-locked)
  huntai lab down <name>       stop a lab target
  huntai lab status            show running lab containers
  huntai serve [host] [port]   launch the web API (default 127.0.0.1:8000)
  huntai tui                   launch the Textual CLI app
  huntai config                show current settings (keys masked)
  huntai config set <k> <v>    set nvidia_api_key|gemini_api_key|ollama_api_key|
                               ollama_host|prefer_offline
  huntai scope list            list user-authorized targets
  huntai scope add <t> --yes   authorize a target (requires --yes ack)"""


def _guard(settings) -> ScopeGuard:
    from .core import load_guard
    return load_guard()


def _cmd_check(settings, target: str) -> int:
    guard = _guard(settings)
    audit = AuditLog(f"{settings.data_dir}/audit.log")
    try:
        t = guard.check(target)
        audit.scope_allow(target)
        console.print(f"[green]IN SCOPE[/] {t.raw} ({t.kind.value})")
        return 0
    except ScopeError as exc:
        audit.scope_deny(target, str(exc))
        console.print(f"[red]OUT OF SCOPE[/] {target}: {exc}")
        return 1


def _cmd_lab(settings, args: list[str]) -> int:
    here = Path(__file__).resolve().parents[2]
    mgr = LabManager(here / "docker" / "labs.yaml", here / "docker" / "docker-compose.yml", _guard(settings))
    audit = AuditLog(f"{settings.data_dir}/audit.log")
    sub = args[0] if args else "list"
    try:
        if sub == "list":
            for lab in mgr.list():
                console.print(f"[cyan]{lab.name:12}[/] {lab.url:28} {lab.description}")
            return 0
        if sub == "status":
            console.print(mgr.status() or "[dim]no lab containers running[/]")
            return 0
        if sub == "up" and len(args) > 1:
            lab = mgr.up(args[1])
            audit.tool_run("lab.up", lab.target, "started")
            console.print(f"[green]LAB UP[/] {lab.name} → {lab.url} (scope-locked)")
            return 0
        if sub == "down" and len(args) > 1:
            mgr.down(args[1])
            console.print(f"[yellow]LAB DOWN[/] {args[1]}")
            return 0
    except LabError as exc:
        console.print(f"[red]lab error:[/] {exc}")
        return 1
    console.print(USAGE)
    return 2


def _cmd_config(settings, args: list[str]) -> int:
    from .core.settings_store import SettingsStore
    store = SettingsStore(f"{settings.data_dir}/settings.json")
    if args and args[0] == "set" and len(args) >= 3:
        key, val = args[1], args[2]
        if key == "prefer_offline":
            val = val.lower() in ("1", "true", "yes")
        store.update({key: val})
        console.print(f"[green]set[/] {key}")
        return 0
    for k, v in store.masked().items():
        console.print(f"  {k}: {v}")
    return 0


def _cmd_scope(args: list[str]) -> int:
    from .core.settings_store import SettingsStore
    settings = get_settings()
    store = SettingsStore(f"{settings.data_dir}/settings.json")
    if args and args[0] == "add" and len(args) > 1:
        ack = "--yes" in args or "-y" in args
        target = args[1]
        try:
            store.add_authorized_target(target, ack)
        except PermissionError as exc:
            console.print(f"[red]refused:[/] {exc}\nre-run with --yes to attest you are authorized.")
            return 1
        console.print(f"[green]authorized[/] {target} (recorded)")
        return 0
    if args and args[0] == "remove" and len(args) > 1:
        store.remove_authorized_target(args[1])
        console.print(f"[yellow]removed[/] {args[1]}")
        return 0
    for t in store.authorized_targets():
        console.print(f"  {t}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    settings = get_settings()

    if not argv:
        console.print(USAGE)
        return 0
    if argv[0] == "check" and len(argv) > 1:
        return _cmd_check(settings, argv[1])
    if argv[0] == "lab":
        return _cmd_lab(settings, argv[1:])
    if argv[0] == "serve":
        host = argv[1] if len(argv) > 1 else "127.0.0.1"
        port = int(argv[2]) if len(argv) > 2 else 8000
        try:
            import uvicorn
        except ImportError:
            console.print("[red]web extra missing:[/] pip install -e \".[web]\"")
            return 1
        console.print(f"[green]HuntAI web[/] → http://{host}:{port}")
        uvicorn.run("huntai.web.app:create_app", host=host, port=port, factory=True)
        return 0
    if argv[0] == "tui":
        from .tui.app import main as tui_main
        tui_main()
        return 0
    if argv[0] == "config":
        return _cmd_config(settings, argv[1:])
    if argv[0] == "scope":
        return _cmd_scope(argv[1:])

    console.print(f"[red]unknown command:[/] {' '.join(argv)}")
    console.print(USAGE)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
