"""FastAPI app — the Svelte frontend and any API client talk to this.

Endpoints:
  GET  /api/health
  GET  /api/labs
  POST /api/assess        {target}       -> report (Auto mode)
  GET  /api/report/{id}
  GET  /api/graph/{id}                    -> mermaid attack graph
  POST /api/copilot       {observation}  -> advisory suggestion
  WS   /api/ws/assess                     -> streamed progress

Inject a fake-runner engine for offline/test via create_app(engine=...).
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ..analysis import build_graph
from ..config import reset_settings
from ..core import HuntAIEngine, build_engine
from ..core.settings_store import SettingsStore
from ..labs import LabManager
from ..scope import ScopeError

ROOT = Path(__file__).resolve().parents[3]


class AssessReq(BaseModel):
    target: str
    name: str = "assessment"


class CopilotReq(BaseModel):
    observation: str


class SettingsReq(BaseModel):
    nvidia_api_key: str | None = None
    gemini_api_key: str | None = None
    ollama_api_key: str | None = None
    ollama_host: str | None = None
    prefer_offline: bool | None = None


class ScopeReq(BaseModel):
    target: str
    authorized: bool = False


class IStartReq(BaseModel):
    target: str


class IStepReq(BaseModel):
    sid: str
    tools: list[str]


class ISidReq(BaseModel):
    sid: str


class ChatReq(BaseModel):
    message: str
    sid: str | None = None


def create_app(engine: HuntAIEngine | None = None) -> FastAPI:
    app = FastAPI(title="HuntAI", version="0.2.0")
    app.state.engine = engine  # may be None -> lazily built (real sandbox)
    app.state.sessions = {}
    app.state.isessions = {}
    app.state.store = SettingsStore(ROOT / "data" / "settings.json")

    def _rebuild():
        """Drop cached settings + engine so new keys/targets take effect."""
        reset_settings()
        app.state.engine = None

    def eng() -> HuntAIEngine:
        if app.state.engine is None:
            app.state.engine = build_engine()
        return app.state.engine

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": "0.2.0"}

    @app.get("/api/labs")
    def labs():
        mgr = LabManager(ROOT / "docker" / "labs.yaml",
                         ROOT / "docker" / "docker-compose.yml", eng().guard)
        return [{"name": lab.name, "url": lab.url, "description": lab.description}
                for lab in mgr.list()]

    @app.post("/api/assess")
    async def assess(req: AssessReq):
        try:
            session = await eng().orchestrator.run_auto(req.target, name=req.name)
        except ScopeError as exc:
            return {"error": "out_of_scope", "detail": str(exc)}
        app.state.sessions[session.id] = session
        return eng().orchestrator.last_report

    @app.get("/api/report/{sid}")
    def report(sid: str):
        session = app.state.sessions.get(sid)
        if session is None:
            return {"error": "not_found"}
        return eng().orchestrator.reporter.report(session)

    @app.get("/api/graph/{sid}")
    def graph(sid: str):
        session = app.state.sessions.get(sid)
        if session is None:
            return {"error": "not_found"}
        return {"mermaid": build_graph(session).to_mermaid()}

    # -- interactive session (human-in-the-loop, step by step) ----------

    @app.post("/api/isession/start")
    async def isession_start(req: IStartReq):
        from ..core.interactive import InteractiveRecon
        ir = InteractiveRecon(eng())
        try:
            t = ir.start(req.target)
        except ScopeError as exc:
            return {"error": "out_of_scope", "detail": str(exc)}
        import uuid
        sid = uuid.uuid4().hex[:8]
        app.state.isessions[sid] = ir
        proposal = await ir.propose()
        return {"sid": sid, "target": t.raw, "kind": t.kind.value, "proposal": proposal}

    @app.post("/api/isession/step")
    async def isession_step(req: IStepReq):
        ir = app.state.isessions.get(req.sid)
        if ir is None:
            return {"error": "not_found"}
        result = await ir.run(req.tools)
        proposal = await ir.propose()
        return {"result": result, "proposal": proposal,
                "findings": [f.model_dump() for f in ir.session.findings]}

    @app.post("/api/isession/finalize")
    def isession_finalize(req: ISidReq):
        ir = app.state.isessions.get(req.sid)
        if ir is None:
            return {"error": "not_found"}
        report = ir.finalize()
        return {"report": report, "mermaid": build_graph(ir.session).to_mermaid()}

    @app.get("/api/settings")
    def get_settings_view():
        return app.state.store.masked()

    @app.post("/api/settings")
    def set_settings(req: SettingsReq):
        patch = {k: v for k, v in req.model_dump().items() if v is not None}
        app.state.store.update(patch)
        _rebuild()
        return app.state.store.masked()

    @app.get("/api/scope")
    def get_scope():
        return {"authorized_targets": app.state.store.authorized_targets()}

    @app.post("/api/scope")
    def add_scope(req: ScopeReq):
        try:
            targets = app.state.store.add_authorized_target(req.target, req.authorized)
        except PermissionError as exc:
            return {"error": "authorization_required", "detail": str(exc)}
        _rebuild()
        return {"authorized_targets": targets}

    @app.post("/api/chat")
    def chat(req: ChatReq):
        from ..agents.prompts import CHAT_SYSTEM
        from ..llm import LLMClient, LLMError
        ctx = ""
        ir = app.state.isessions.get(req.sid) if req.sid else None
        if ir is not None and ir.session and ir.session.findings:
            ctx = "Current findings:\n" + "\n".join(
                f"- [{f.severity.value}] {f.title} {f.cve_ids or ''} {f.mitre_techniques or ''}"
                for f in ir.session.findings) + "\n\n"
        try:
            reply = LLMClient().complete(CHAT_SYSTEM, ctx + "Operator: " + req.message)
        except LLMError as exc:
            reply = f"(LLM unavailable — {exc}) Configure a provider key in settings to chat."
        return {"reply": reply}

    @app.post("/api/copilot")
    def copilot(req: CopilotReq):
        sug = eng().orchestrator.as_copilot().observe(req.observation)
        return {"summary": sug.summary, "next_tools": sug.next_tools,
                "rationale": sug.rationale, "kb_refs": sug.kb_refs}

    @app.websocket("/api/ws/assess")
    async def ws_assess(ws: WebSocket):
        await ws.accept()
        try:
            data = await ws.receive_json()
            target = data.get("target", "")
            await ws.send_json({"event": "start", "target": target})
            try:
                session = await eng().orchestrator.run_auto(target)
            except ScopeError as exc:
                await ws.send_json({"event": "error", "detail": str(exc)})
                await ws.close()
                return
            app.state.sessions[session.id] = session
            for t in session.tasks:
                await ws.send_json({"event": "task", "title": t.title, "status": t.status.value})
            await ws.send_json({"event": "done", "session": session.id,
                                "findings": len(session.findings)})
        except WebSocketDisconnect:
            return
        await ws.close()

    # serve built Svelte app if present
    dist = ROOT / "web" / "frontend" / "dist"
    if dist.exists():
        from fastapi.staticfiles import StaticFiles
        app.mount("/", StaticFiles(directory=str(dist), html=True), name="frontend")

    return app
