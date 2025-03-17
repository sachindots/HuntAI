# HuntAI Web (Svelte)

Frontend for the HuntAI FastAPI backend.

```bash
# backend (from repo root)
uvicorn huntai.web.app:create_app --factory --reload   # http://localhost:8000

# frontend (this dir)
npm install
npm run dev        # http://localhost:5173, proxies /api -> :8000
npm run build      # -> dist/, then FastAPI serves it at /
```

Modes: **Auto** (drive an assessment against a lab target) and **Copilot**
(paste an observation, get a suggested next step). The attack graph renders as
Mermaid.
