# HuntAI — Architecture

This document explains how HuntAI is put together: the components, how a request
flows through them, and the design decisions behind the structure.

## Design principles

1. **The LLM orchestrates, code enforces.** The model decides *what* recon to do;
   scope, approval, and execution are enforced by code the model cannot bypass.
2. **Everything typed.** Data crossing any boundary (tool → agent → UI) is a
   Pydantic model. No free-text scraping.
3. **Token discipline.** The LLM never blocks on a slow tool and never sees raw
   tool dumps — only compacted summaries.
4. **One core, many faces.** CLI, Web, and TUI all call the same engine factory.
5. **Safe by construction.** A target that fails the scope guard can never reach a tool.

---

## Component map

```mermaid
flowchart LR
    subgraph Interfaces
        CLI[CLI / Textual TUI]
        WEB[FastAPI + Svelte]
    end

    subgraph Core
        F[Engine Factory<br/>build_engine]
        ORC[Orchestrator]
        SET[(Settings store)]
    end

    subgraph Agents
        AG[Agentic Recon<br/>LLM loop]
        RB[Rule-based Recon<br/>fallback]
        ANA[Analysis]
        VAL[Validation]
        REP[Reporter]
        COP[Copilot]
    end

    subgraph Engine
        DIS[Dispatcher<br/>async · concurrent]
        RUN[Runners:<br/>Sandbox · Native · Fake]
        CMP[Compaction<br/>+ token budget]
    end

    subgraph Knowledge
        CAG[(CAG store)]
        MEM[(Findings memory)]
    end

    subgraph Intelligence
        MIT[MITRE mapping]
        CVE[CVE correlation]
        GRA[Attack graph]
    end

    CLI & WEB --> F --> ORC
    SET --> F
    ORC --> AG & ANA & VAL & REP & COP
    AG --> RB
    AG --> DIS --> RUN --> CMP
    ANA --> MIT & CVE & GRA
    CAG & MEM -.-> AG & COP
```

---

## Request lifecycle (Auto mode)

```mermaid
flowchart TD
    A[User submits target] --> B{Scope guard}
    B -- out of scope --> Bx[Reject + audit]
    B -- in scope --> C[Agentic loop starts]
    C --> D[LLM: decide next tools<br/>from results so far]
    D --> E{Active tool?}
    E -- yes --> F{Human approval}
    F -- deny --> D
    F -- approve --> G
    E -- no/passive --> G[Dispatch concurrently]
    G --> H[Runner executes<br/>sandbox or native]
    H --> I[Typed parse → ToolResult]
    I --> J[Compact summary → LLM]
    J --> K{LLM: done?}
    K -- no --> D
    K -- yes --> L[Analysis · dedup]
    L --> M[Intelligence:<br/>MITRE + CVE + graph]
    M --> N[Validation:<br/>confidence + anti-FP]
    N --> O[Report + attack graph]
```

Key property: the loop is bounded by a **max-iteration cap** and a **token
budget**. If the LLM is unavailable, the very first decision falls back to a
deterministic rule-based plan, so the system always makes progress.

---

## The knowledge split (CAG vs memory)

The original project conflated RAG and CAG. HuntAI keeps them **separate** and
uses each for what it's good at:

```mermaid
flowchart LR
    subgraph CAG["CAG — static, preloaded"]
        C1[Methodology cheatsheet<br/>OWASP · PTES · ports]
        C2[Long-context model<br/>KV-cache reuse]
        C1 --> C2
    end
    subgraph MEM["Memory — dynamic, retrieved"]
        M1[Session findings]
        M2[BM25 + dense<br/>reciprocal-rank fusion]
        M1 --> M2
    end
    C2 -. grounds planning .-> LLM[LLM]
    M2 -. recalls prior findings .-> LLM
```

- **CAG** — a bounded, stable cheatsheet preloaded once and reused (no retrieval).
  Right for knowledge that doesn't change mid-engagement.
- **Memory** — dynamic per-session findings, retrieved on demand with hybrid search.
  Right for the growing, query-dependent knowledge.

---

## Token-discipline engine

Slow tools (an `nmap` can take minutes) must not burn tokens.

```mermaid
sequenceDiagram
    participant L as LLM
    participant D as Dispatcher
    participant T as Tool (slow)
    L->>D: emit tool calls
    Note over L: LLM turn ENDS — 0 tokens while waiting
    D->>T: run concurrently (bg)
    T-->>D: raw output
    D->>D: parse + summarize (raw stays on disk)
    D-->>L: compact digest only
    Note over L: next turn resumes with summaries
```

- Tools run **detached** from the LLM turn.
- Results are **parsed and summarized** before feedback — raw output is never re-sent.
- Multiple finished tools are **batched** into one LLM call.
- A `TokenBudget` charges summaries (not raw) and caps total spend.

---

## Runners: same tools, different execution

```mermaid
flowchart LR
    T[Tool.build_argv] --> R{Runner}
    R -->|SandboxRunner| D[docker compose exec<br/>isolated container]
    R -->|NativeRunner| N[subprocess on host<br/>Kali / Parrot]
    R -->|FakeRunner| F[replay fixtures<br/>tests / offline]
```

The agent, scope guard, and parsers are identical across runners — only *where*
the tool executes changes. This is why the same code runs in a Docker sandbox on
Windows and natively on a Kali box.

---

## Model routing

`config.Settings.route(role)` maps a role to a free provider, with fallback:

| Role | Primary | Fallback |
|------|---------|----------|
| Reasoning / orchestration | NVIDIA NIM | Ollama (local) |
| Long-context (CAG) | Gemini | Ollama |
| Parsing (high volume) | Ollama | — |
| Embeddings | Ollama (`bge-m3`) | — |

All three providers are OpenAI-compatible, so a single `openai`-SDK client drives
them. Set `prefer_offline` to route everything to Ollama — no cloud, no keys.

---

## Safety enforcement points

```mermaid
flowchart TD
    T[Target / tool request] --> S{Scope guard}
    S -->|deny rules win| X1[Reject]
    S -->|not authorized| X2[Reject]
    S -->|ok| A{Approval gate}
    A -->|active + denied| X3[Skip + audit]
    A -->|passive / approved| V{Tool in registry?}
    V -->|no| X4[Drop — LLM cannot invent tools]
    V -->|yes| E[Execute]
    E --> AU[(Audit log)]
```

Four independent checks, all in code: scope → approval → registry validation →
audit. The LLM participates in *planning* but sits inside these rails.
