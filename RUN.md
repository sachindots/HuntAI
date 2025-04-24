# Running HuntAI — step by step

Works on **Ubuntu** and **Windows** (identical, because tools run in Docker).
Times assume a normal broadband connection.

---

## 0. Prerequisites (install once)

| Tool | Ubuntu | Windows |
|------|--------|---------|
| **Python 3.11+** | `sudo apt install python3 python3-venv` | python.org installer |
| **Docker** (tools + labs) | `sudo apt install docker.io && sudo usermod -aG docker $USER` | Docker Desktop (enable WSL2) |
| **Ollama** (local models) | `curl -fsSL https://ollama.com/install.sh \| sh` | ollama.com installer |
| **Node 18+** (web UI, optional) | `sudo apt install nodejs npm` | nodejs.org installer |

After installing Ollama, pull the local models:
```bash
ollama pull qwen3:8b       # reasoning fallback
ollama pull qwen3:4b       # fast parsing
ollama pull bge-m3         # embeddings
```

Free API keys (optional — skip for fully-local):
- NVIDIA NIM: https://build.nvidia.com  → `HUNTAI_NVIDIA_API_KEY`
- Gemini: https://aistudio.google.com    → `HUNTAI_GEMINI_API_KEY`

---

## 1. Install HuntAI

```bash
cd HuntAI
python -m venv .venv
# Ubuntu:  source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -e ".[dev,web,llm]"
```

> The LLM layer uses the `openai` SDK — every provider (NVIDIA NIM, Ollama,
> Gemini) is OpenAI-compatible, so one lightweight SDK drives them all. Installs
> cleanly on Python 3.11–3.14, no Rust. Skip the `llm` extra and the LLM
> orchestrator/analyst fall back to deterministic rule-based behavior.

## 2. Configure

Two ways — pick either:

**A. In the app (recommended)** — start it and set keys/targets from the UI or CLI:
```bash
huntai config set nvidia_api_key nvapi-xxxx
huntai config set ollama_host http://localhost:11434
huntai config                       # view (keys masked)
huntai scope add 203.0.113.7 --yes  # authorize YOUR target (attestation required)
```
The web UI has the same under the ⚙ settings panel. Keys are stored in
`data/settings.json` (gitignored) and never printed back in full.

**B. .env file**
```bash
cp .env.example .env          # Windows: copy .env.example .env
# add keys, OR set HUNTAI_PREFER_OFFLINE=true for fully local
```

## 3. Verify it works (no Docker needed)

```bash
pytest                        # 106 tests pass
huntai check 172.20.0.5       # IN SCOPE
huntai check 8.8.8.8          # OUT OF SCOPE (blocked)
```

## 4. Preflight — what's ready on your machine

```bash
python scripts/smoke.py --check
```
Reports Docker / Ollama / NIM / openai SDK status. Everything degrades gracefully.

---

## 5. Run a real assessment (needs Docker)

### One-shot smoke test (spins DVWA, scans it, tears down)
```bash
python scripts/smoke.py
```

### Manual
```bash
# start a vulnerable lab target (scope-locked to 172.20.0.0/16)
huntai lab up dvwa
huntai lab list
huntai lab status

# assess it from the CLI TUI
huntai tui                    # type 172.20.0.10, watch findings stream

# stop the lab
huntai lab down dvwa
```

---

## 6. Web UI (Svelte + FastAPI)

Terminal 1 — backend:
```bash
huntai serve                  # http://127.0.0.1:8000  (API + WS)
```
Terminal 2 — frontend (dev):
```bash
cd web/frontend
npm install
npm run dev                   # http://localhost:5173  (proxies /api -> :8000)
```
Or build once and let FastAPI serve it:
```bash
cd web/frontend && npm run build      # -> dist/
huntai serve                          # now serves the UI at http://127.0.0.1:8000/
```

---

## 6b. Scan your own target (not just labs)

HuntAI is scope-locked. To point it at a system you own or are authorized to
test, authorize the target first (records your attestation, still blocks cloud
metadata / CGNAT ranges):
```bash
huntai scope add 203.0.113.7 --yes      # or a CIDR / hostname
huntai check 203.0.113.7                # -> IN SCOPE
```
Then assess it in the TUI / web UI exactly like a lab. Only test what you are
legally authorized to.

## 7. Modes

- **Auto** — enter a lab target, HuntAI plans → scans (you approve active steps) →
  analyzes → reports with MITRE + CVE + attack graph.
- **Copilot** — paste any tool output/observation; HuntAI suggests the next step,
  grounded in the KB. Runs nothing.

Toggle in the web UI header, or pick per call in code
(`orchestrator.run_auto` vs `orchestrator.as_copilot().observe`).

---

## 8. Fully local / offline

```bash
# .env
HUNTAI_PREFER_OFFLINE=true
```
All reasoning + parsing + embeddings route to Ollama. No cloud, no keys.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `docker not found` in preflight | install Docker, start the daemon |
| `ollama not reachable` | `ollama serve` running? default `localhost:11434` |
| LLM planner "falls back to rule-based" | install `.[llm]` + set a key, or it stays deterministic (fine) |
| Windows glyphs look odd | already handled — scripts force UTF-8 / ASCII markers |
| out-of-scope error | target not in `scope.yaml`; labs use `172.20.0.0/16` only |
