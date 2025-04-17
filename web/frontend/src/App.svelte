<script>
  import { afterUpdate } from "svelte";

  let messages = [];
  let input = "";
  let sid = null;
  let target = null;
  let busy = false;
  let proposal = null;
  let feed;
  let showSettings = false;

  let settings = { authorized_targets: [] };
  let form = { nvidia_api_key: "", gemini_api_key: "", ollama_host: "", prefer_offline: false };
  let scopeTarget = "", scopeAck = false, scopeMsg = "";

  const BANNER = String.raw`
  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗ █████╗ ██╗
  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔══██╗██║
  ███████║██║   ██║██╔██╗ ██║   ██║   ███████║██║
  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══██║██║
  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ██║  ██║██║
  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝╚═╝`;

  const sevColor = (s) => ({ critical:"#ff2e63", high:"#ff5c00", medium:"#ffb000", low:"#c8d600", info:"#00e0ff" }[s] || "#00e0ff");

  function push(role, text, data = null) { messages = [...messages, { role, text, data }]; }

  afterUpdate(() => { if (feed) feed.scrollTop = feed.scrollHeight; });

  function boot() {
    push("banner", BANNER);
    push("sys", "HuntAI recon console // authorized targets only");
    push("sys", "type a target to begin  ·  'help' for commands");
  }
  boot();

  async function submit() {
    const raw = input.trim();
    if (!raw || busy) return;
    input = "";
    push("you", raw);
    const [cmd, ...rest] = raw.split(/\s+/);
    const lc = cmd.toLowerCase();

    if (lc === "help") return help();
    if (lc === "clear") { messages = []; return boot(); }
    if (lc === "finish" || lc === "report") return finish();
    if (lc === "settings") { showSettings = true; return; }
    if (lc === "run") {
      if (!sid) return push("ai", "no active session — enter a target first.");
      const tools = rest.length ? rest : (proposal?.tools || []).map((t) => t.tool);
      return runTools(tools);
    }
    if (!sid) return startSession(raw);
    // free text with an active session -> chat with HuntAI (LLM)
    return chat(raw);
  }

  function help() {
    push("sys", [
      "commands:",
      "  <target>            start a recon session (e.g. preview.owasp-juice.shop)",
      "  run [tool ...]      execute proposed tools, or named ones (run httpx nmap)",
      "  finish              analyze + generate report",
      "  <question>          ask HuntAI anything about the findings",
      "  settings · clear",
    ].join("\n"));
  }

  async function startSession(t) {
    busy = true; push("ai", `scoping ${t} …`);
    try {
      const r = await api("/api/isession/start", { target: t });
      if (r.error) { push("ai", `⛔ ${r.detail || r.error}`); return; }
      sid = r.sid; target = r.target;
      push("ai", `target in scope: ${r.target} (${r.kind}). session ${r.sid} open.`);
      setProposal(r.proposal);
    } finally { busy = false; }
  }

  function setProposal(p) {
    proposal = p;
    if (!p) return;
    if (p.done && !(p.tools || []).length) {
      push("ai", "recon looks complete. type 'finish' for the report.", { done: true });
    } else {
      push("ai", p.rationale || "next step:", { proposal: p });
    }
  }

  async function runTools(tools) {
    if (!tools.length) return;
    busy = true; push("run", `executing: ${tools.join(", ")}`);
    try {
      const r = await api("/api/isession/step", { sid, tools });
      for (const res of r.result?.results || [])
        push("tool", `${res.tool}: ${res.summary || res.error}`, { status: res.status });
      const known = new Set(messages.filter((m) => m.role === "finding").map((m) => m.text));
      for (const f of r.findings || []) {
        const key = f.title + f.target;
        if (!known.has(key)) push("finding", f.title, { f, key });
      }
      setProposal(r.proposal);
    } finally { busy = false; }
  }

  async function finish() {
    if (!sid) return push("ai", "no session to finalize.");
    busy = true; push("ai", "correlating findings · MITRE · CVE · building report …");
    try {
      const r = await api("/api/isession/finalize", { sid });
      const rep = r.report || {};
      push("report", "assessment report", { rep, mermaid: r.mermaid });
      if (rep.executive_summary) push("ai", rep.executive_summary);
    } finally { busy = false; }
  }

  async function chat(msg) {
    busy = true; push("ai", "…", { thinking: true });
    try {
      const r = await api("/api/chat", { message: msg, sid });
      messages = messages.filter((m) => !m.data?.thinking);
      push("ai", r.reply || "(no reply)");
    } finally { busy = false; }
  }

  const api = (url, body) =>
    fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }).then((r) => r.json());

  // settings
  async function openSettings() {
    showSettings = true;
    settings = await fetch("/api/settings").then((r) => r.json());
    form.ollama_host = settings.ollama_host || ""; form.prefer_offline = settings.prefer_offline || false;
  }
  async function saveSettings() {
    const patch = { prefer_offline: form.prefer_offline };
    for (const k of ["nvidia_api_key","gemini_api_key","ollama_host"]) if (form[k]) patch[k] = form[k];
    settings = await api("/api/settings", patch); form.nvidia_api_key = form.gemini_api_key = "";
    push("sys", "settings updated.");
  }
  async function addScope() {
    scopeMsg = "";
    const r = await api("/api/scope", { target: scopeTarget, authorized: scopeAck });
    if (r.error) { scopeMsg = r.detail; return; }
    settings.authorized_targets = r.authorized_targets; scopeTarget = ""; scopeAck = false; scopeMsg = "authorized";
  }
</script>

<div class="crt">
  <div class="scan"></div>
  <header>
    <span class="dot"></span><span class="dot a"></span><span class="dot g"></span>
    <span class="ttl">huntai@recon:~</span>
    <span class="status">{sid ? `● ${target}` : "○ idle"}</span>
    <button class="gear" on:click={openSettings}>[ settings ]</button>
  </header>

  <div class="feed" bind:this={feed}>
    {#each messages as m}
      {#if m.role === "banner"}
        <pre class="banner">{m.text}</pre>
      {:else if m.role === "sys"}
        <div class="sys">{m.text}</div>
      {:else if m.role === "you"}
        <div class="line"><span class="pu">operator&gt;</span> {m.text}</div>
      {:else if m.role === "run"}
        <div class="line run"><span class="pr">exec&gt;</span> {m.text}</div>
      {:else if m.role === "tool"}
        <div class="tool {m.data?.status}"><span class="mark">{m.data?.status === "success" ? "✓" : "✗"}</span> {m.text}</div>
      {:else if m.role === "finding"}
        <div class="finding" style="border-color:{sevColor(m.data.f.severity)};color:{sevColor(m.data.f.severity)}">
          <b>[{m.data.f.severity.toUpperCase()}]</b> {m.data.f.title}
          {#if m.data.f.cve_ids?.length}<span class="tag">{m.data.f.cve_ids.join(" ")}</span>{/if}
          {#if m.data.f.mitre_techniques?.length}<span class="tag mitre">{m.data.f.mitre_techniques.join(" ")}</span>{/if}
        </div>
      {:else if m.role === "report"}
        <div class="report">
          <div class="rh">── {m.text} ──</div>
          <div class="sevrow">{#each Object.entries(m.data.rep.by_severity || {}) as [k,v]}{#if v}<span class="pill" style="background:{sevColor(k)}">{k}:{v}</span>{/if}{/each}</div>
          {#if m.data.mermaid}<pre class="graph">{m.data.mermaid}</pre>{/if}
        </div>
      {:else}
        <div class="line ai"><span class="pa">huntai&gt;</span>
          {#if m.data?.thinking}<span class="blink">▓▓▓</span>{:else}{m.text}{/if}
          {#if m.data?.proposal}
            <div class="prop">
              {#each m.data.proposal.tools as t}
                <button class="chip" on:click={() => runTools([t.tool])} disabled={busy}>▶ {t.tool}</button>
              {/each}
              {#if m.data.proposal.tools.length > 1}
                <button class="chip all" on:click={() => runTools(m.data.proposal.tools.map((x)=>x.tool))} disabled={busy}>▶ run all</button>
              {/if}
            </div>
          {/if}
          {#if m.data?.done}<div class="prop"><button class="chip all" on:click={finish} disabled={busy}>■ finish &amp; report</button></div>{/if}
        </div>
      {/if}
    {/each}
  </div>

  <div class="promptbar">
    <span class="ps1">hunter@huntai:~$</span>
    <input bind:value={input} on:keydown={(e) => e.key === "Enter" && submit()}
           placeholder={sid ? "run · ask a question · finish" : "enter target to begin…"}
           spellcheck="false" autocomplete="off" />
    <span class="cursor" class:on={busy}>_</span>
  </div>

  {#if showSettings}
    <div class="modal" on:click={() => showSettings = false}>
      <div class="mbox" on:click|stopPropagation>
        <div class="rh">── config ──</div>
        {#each [["nvidia_api_key","NVIDIA NIM key"],["gemini_api_key","Gemini key"]] as [k,label]}
          <label>{label}<input type="password" bind:value={form[k]} placeholder={settings[k] || "not set"} /></label>
        {/each}
        <label>Ollama host<input bind:value={form.ollama_host} placeholder="http://localhost:11434" /></label>
        <label class="chk"><input type="checkbox" bind:checked={form.prefer_offline} /> fully offline (Ollama)</label>
        <button on:click={saveSettings}>save</button>
        <div class="rh">── authorize target ──</div>
        <label>target<input bind:value={scopeTarget} placeholder="ip / cidr / host" /></label>
        <label class="chk warn"><input type="checkbox" bind:checked={scopeAck} /> I am authorized to test this</label>
        <button on:click={addScope}>authorize</button> <span class="msg">{scopeMsg}</span>
        {#if settings.authorized_targets?.length}<div class="tl">{settings.authorized_targets.join("  ·  ")}</div>{/if}
        <button class="close" on:click={() => showSettings = false}>close</button>
      </div>
    </div>
  {/if}
</div>

<style>
  :global(body){margin:0;background:#05070a}
  .crt{--g:#00ff9c;--g2:#00c27a;--amber:#ffb000;font-family:"JetBrains Mono",ui-monospace,"Cascadia Code",Consolas,monospace;
    background:radial-gradient(ellipse at 50% 0%,#0b1410 0%,#05070a 70%);color:var(--g);min-height:100vh;
    display:flex;flex-direction:column;max-width:920px;margin:0 auto;position:relative;font-size:13.5px;line-height:1.5}
  .scan{position:absolute;inset:0;pointer-events:none;z-index:5;
    background:repeating-linear-gradient(180deg,rgba(0,255,156,.03) 0 1px,transparent 1px 3px)}
  header{display:flex;align-items:center;gap:8px;padding:10px 14px;border-bottom:1px solid #123;background:#080d10}
  .dot{width:11px;height:11px;border-radius:50%;background:#ff2e63}.dot.a{background:var(--amber)}.dot.g{background:var(--g)}
  .ttl{color:var(--g2);margin-left:6px}.status{margin-left:auto;color:var(--amber);font-size:12px}
  .gear{background:none;border:1px solid #123;color:var(--g2);cursor:pointer;font-family:inherit;font-size:11px;padding:3px 8px}
  .feed{flex:1;overflow-y:auto;padding:14px;min-height:420px;max-height:70vh}
  .banner{color:var(--g);text-shadow:0 0 8px rgba(0,255,156,.5);font-size:9px;line-height:1.1;margin:0 0 6px}
  .sys{color:#4a6b5c;white-space:pre-wrap;margin:2px 0}
  .line{margin:5px 0;white-space:pre-wrap;word-break:break-word}
  .pu{color:var(--amber)}.pr{color:#ff5c00}.pa{color:var(--g);text-shadow:0 0 6px rgba(0,255,156,.6)}
  .line.ai{color:#c9ffe9}
  .tool{margin:3px 0 3px 14px;color:var(--g2)}.tool.failed{color:#ff5c66}.tool .mark{opacity:.8}
  .finding{margin:5px 0 5px 14px;padding:4px 10px;border-left:3px solid;background:rgba(0,0,0,.3)}
  .tag{font-size:11px;color:#8fb;margin-left:6px;opacity:.85}.tag.mitre{color:var(--amber)}
  .prop{margin:6px 0 2px;display:flex;gap:8px;flex-wrap:wrap}
  .chip{background:#04120c;border:1px solid var(--g2);color:var(--g);font-family:inherit;font-size:12px;
    padding:4px 12px;cursor:pointer;transition:.15s}
  .chip:hover{background:var(--g2);color:#04120c;box-shadow:0 0 10px rgba(0,255,156,.5)}
  .chip.all{border-color:var(--amber);color:var(--amber)}.chip.all:hover{background:var(--amber);color:#111}
  .chip:disabled{opacity:.4;cursor:wait}
  .report{margin:8px 0 8px 14px}.rh{color:var(--g2);margin:8px 0 4px}
  .sevrow{margin:4px 0}.pill{color:#04120c;font-weight:bold;font-size:11px;padding:2px 9px;margin-right:6px}
  .graph{background:#080d10;border:1px solid #123;padding:10px;color:#7fe;font-size:11px;overflow-x:auto;margin-top:6px}
  .blink{animation:bl 1s steps(2) infinite}@keyframes bl{50%{opacity:.2}}
  .promptbar{display:flex;align-items:center;gap:8px;padding:12px 14px;border-top:1px solid #123;background:#080d10;position:sticky;bottom:0}
  .ps1{color:var(--g);text-shadow:0 0 6px rgba(0,255,156,.6);white-space:nowrap}
  .promptbar input{flex:1;background:none;border:none;outline:none;color:#c9ffe9;font-family:inherit;font-size:13.5px}
  .cursor{color:var(--g);animation:bl 1s steps(2) infinite}.cursor.on{color:var(--amber)}
  .modal{position:absolute;inset:0;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;z-index:20}
  .mbox{background:#080d10;border:1px solid var(--g2);padding:18px;width:min(440px,90%);box-shadow:0 0 30px rgba(0,255,156,.15)}
  .mbox label{display:block;color:#8fb;font-size:12px;margin:8px 0}
  .mbox input[type=password],.mbox input:not([type]){display:block;width:100%;box-sizing:border-box;margin-top:3px;background:#04120c;border:1px solid #123;color:var(--g);font-family:inherit;padding:6px}
  .mbox .chk{color:#8fb}.mbox .chk.warn{color:var(--amber)}
  .mbox button{background:#04120c;border:1px solid var(--g2);color:var(--g);font-family:inherit;padding:6px 14px;cursor:pointer;margin-top:6px}
  .mbox .close{border-color:#345;color:#8fb;float:right}
  .msg{color:var(--g);font-size:12px}.tl{color:#5a8;font-size:11px;margin-top:8px;word-break:break-all}
</style>
