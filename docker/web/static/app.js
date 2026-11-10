/* Vulnerator Console — frontend (vanilla, sin dependencias).
 *
 * Datos: API de vulnerator-web (/api/*) + stream SSE (/api/stream, reanudable).
 * Seguridad: TODO lo que llega del agente/tools/Caido es DATO NO CONFIABLE; se pinta
 * SIEMPRE con textContent vía h(), nunca con innerHTML.
 */
"use strict";

(() => {
  // ───────────────────────────────────────────────────────── utilidades
  const $ = (id) => document.getElementById(id);

  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") el.className = v;
        else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
        else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
        else el.setAttribute(k, v === true ? "" : String(v));
      }
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

  let skew = 0; // segundos: reloj del servidor - reloj del navegador
  const now = () => Date.now() / 1000 + skew;

  function fmtDur(s) {
    if (s === null || s === undefined || isNaN(s)) return "—";
    s = Math.max(0, s);
    if (s < 1) return Math.round(s * 1000) + "ms";
    if (s < 60) return (s < 10 ? s.toFixed(2) : s.toFixed(1)) + "s";
    if (s < 3600) return Math.floor(s / 60) + "m " + String(Math.floor(s % 60)).padStart(2, "0") + "s";
    return Math.floor(s / 3600) + "h " + String(Math.floor((s % 3600) / 60)).padStart(2, "0") + "m";
  }
  function fmtTime(ts) {
    if (!ts) return "—";
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString("es-ES", { hour12: false, timeZone: TZ });
  }
  function fmtDateTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleString("es-ES", { hour12: false, dateStyle: "short", timeStyle: "medium", timeZone: TZ });
  }
  function fmtAgo(ts) {
    if (!ts) return "—";
    const s = Math.max(0, now() - ts);
    if (s < 10) return "ahora";
    if (s < 60) return "hace " + Math.floor(s) + "s";
    if (s < 3600) return "hace " + Math.floor(s / 60) + "m";
    if (s < 86400) return "hace " + Math.floor(s / 3600) + "h";
    return "hace " + Math.floor(s / 86400) + "d";
  }
  function fmtBytes(n) {
    if (n === null || n === undefined) return "—";
    if (n < 1024) return n + "";
    if (n < 1048576) return (n / 1024).toFixed(1) + "k";
    return (n / 1048576).toFixed(1) + "M";
  }
  function fmtInt(n) { return n === null || n === undefined ? "—" : Number(n).toLocaleString("es-ES"); }
  function oneLine(s, n = 200) {
    s = String(s || "").replace(/\s+/g, " ").trim();
    return s.length > n ? s.slice(0, n - 1) + "…" : s;
  }

  const CAT_LABEL = {
    shell: "shell", browser: "navegador", web: "web", finding: "hallazgo", recon: "recon",
    tracking: "tracking", subagent: "subagente", tool: "otras",
  };
  const OODA_LINE = /^[\s>*_`#]*OODA\s*[—–\-:]+\s*[*_`]*(OBSERVE|ORIENT|DECIDE|ACT|REPORT)\b/i;
  const isFinding = (ev) => String(ev.tool || "").endsWith("record_finding");

  // Salida útil de una tool (espejo de event_model.tool_output_text).
  function unwrap(text) {
    const s = String(text || "").trim();
    if (!s || !"{[".includes(s[0])) return null;
    let doc;
    try { doc = JSON.parse(s); } catch (_) { return null; }
    for (let i = 0; i < 3; i++) {
      if (doc && typeof doc === "object" && !Array.isArray(doc)) {
        const keys = Object.keys(doc);
        if (keys.length && keys.every((k) => ["result", "structuredContent", "content", "isError"].includes(k))) {
          let inner = doc.structuredContent || doc.result;
          if (inner == null && Array.isArray(doc.content)) inner = doc.content;
          if (inner == null) break;
          doc = inner; continue;
        }
      }
      if (Array.isArray(doc) && doc.length && doc.every((p) => p && typeof p === "object")) {
        const texts = doc.filter((p) => p.type === "text" && typeof p.text === "string").map((p) => p.text);
        if (texts.length === 1) {
          try { doc = JSON.parse(texts[0]); continue; } catch (_) { return { output: texts[0] }; }
        }
      }
      if (typeof doc === "string") {
        try { doc = JSON.parse(doc); continue; } catch (_) { return { output: doc }; }
      }
      break;
    }
    return doc;
  }
  function outputText(text) {
    const d = unwrap(text);
    if (d && typeof d === "object" && !Array.isArray(d)) {
      if (typeof d.output === "string") return d.output;
      const parts = ["stdout", "stderr"].map((k) => d[k]).filter((v) => typeof v === "string" && v);
      if (parts.length) return parts.join("\n");
      return JSON.stringify(d, null, 2);
    }
    if (Array.isArray(d)) return JSON.stringify(d, null, 2);
    return String(text || "");
  }

  async function api(path) {
    const r = await fetch(path, { credentials: "same-origin", cache: "no-store" });
    if (r.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname) + location.hash; throw new Error("sesión caducada"); }
    if (!r.ok) throw new Error(path + " → HTTP " + r.status);
    return r.json();
  }

  function throttle(fn, ms) {
    let t = null, pending = false;
    return function () {
      if (t) { pending = true; return; }
      fn();
      t = setTimeout(() => { t = null; if (pending) { pending = false; fn(); } }, ms);
    };
  }

  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  // Zona horaria fija para TODA la consola (independiente del reloj/TZ del host).
  const TZ = "Europe/Madrid";

  // ───────────────────────────────────────────────────────── estado
  const S = {
    childTraces: {},       // sid hija -> traza (nodos de subagente del grafo)
    graphSel: null,        // nodo seleccionado del grafo: "hermes" | "fam:<cat>" | "sub:<sid>" | "tgt:<host>"
    graphOpen: new Set(),  // call_id desplegadas en el panel del grafo
    evCache: new Map(),    // seq -> evento completo (args/resultado) ya pedido
    toolSelected: null,    // nombre de tool elegido en "Por herramienta" (tabla de Trazas)
    status: null,
    sessions: [],
    sid: null,
    session: null,
    view: "terminal",
    events: [],
    lastSeq: 0,
    loading: false,
    pending: [],
    calls: new Map(),      // call_id -> {ev, result, statusEl, anchor}
    web: [],
    lastActivity: 0,
    trace: null,
    traceSelected: null,
    pocs: [],
    pocSelected: null,
    pocSev: "all",         // filtro de severidad: all|critical|high|medium|low|info
    aiSev: {},             // veredicto de severidad de la IA: título -> {severity,cvss,rationale}
    knownPocs: null,       // Map id -> store_status (null hasta la primera carga)
    player: null,
  };

  // ───────────────────────────────────────────────────────── vistas / tabs
  const VIEWS = ["terminal", "copilot", "traces", "pocs", "pantallas", "hermes"];

  function showView(view) {
    if (!VIEWS.includes(view)) view = "terminal";
    S.view = view;
    for (const v of VIEWS) {
      $("view-" + v).hidden = v !== view;
      $("tab-" + v).setAttribute("aria-selected", v === view ? "true" : "false");
    }
    if (location.hash.slice(1) !== view) history.replaceState(null, "", "#" + view);
    if (view === "copilot") renderCopilot();
    if (view === "traces") loadTrace();
    else if (typeof wfTip !== "undefined") wfTip.hidden = true;
    if (view === "pocs") { loadPocs(); }
    if (view === "pantallas") renderScreens();
    if (view === "terminal") scrollTermSoon(true);
  }
  document.querySelectorAll(".tab").forEach((b) => b.addEventListener("click", () => showView(b.dataset.view)));
  window.addEventListener("hashchange", () => showView(location.hash.slice(1)));

  // ───────────────────────────────────────────────────────── salud
  function setPill(id, state, label, title) {
    const el = $(id);
    el.dataset.state = state;
    if (label !== undefined) {
      const b = el.querySelector("b");
      if (b) b.textContent = label;
    }
    if (title) el.title = title;
  }

  async function loadStatus() {
    try {
      const st = await api("/api/status");
      S.status = st;
      skew = st.now - Date.now() / 1000;
      const ing = st.ingest || {};
      const ver = ing.hermes_version ? "v" + String(ing.hermes_version).replace(/^v/, "") : "?";
      setPill("pill-hermes", ing.ok ? "ok" : "err", ver,
        ing.ok ? "API de Hermes accesible" : "Hermes no responde: " + (ing.last_error || "sin datos"));
      const age = ing.last_poll ? now() - ing.last_poll : 999;
      setPill("pill-ingest", ing.ok && age < 10 ? "ok" : "warn", undefined,
        "Último sondeo " + fmtAgo(ing.last_poll) + " · " + (ing.sessions || 0) + " sesiones · " +
        (ing.pocs_recorded || 0) + " PoC grabados");
      const c = st.caido || {};
      if (!c.enabled) setPill("pill-caido", "off", undefined, "Feed de Caido desactivado");
      else setPill("pill-caido", c.ok ? "ok" : "err", undefined,
        c.ok ? "Caido: " + fmtInt(c.requests) + " peticiones en el historial" : "Caido: " + (c.last_error || "sin datos"));
      setupHermesLinks();
    } catch (e) {
      setPill("pill-hermes", "err", "?", String(e));
    }
    updateLive();
  }

  function updateLive() {
    const running = S.sessions.some((s) => (s.running || 0) > 0);
    const recent = now() - S.lastActivity < 15;
    setPill("pill-live", running || recent ? "on" : "off", undefined,
      running ? "Hay herramientas ejecutándose ahora mismo" : recent ? "Actividad en los últimos segundos" : "Sin actividad");
  }

  // ───────────────────────────────────────────────────────── sesiones
  function sessionLabel(s) {
    return oneLine(s.title || s.preview || s.id, 90);
  }
  function isLive(s) { return (s.running || 0) > 0 || (s.last_active && now() - s.last_active < 20); }

  function orderedSessions() {
    const byParent = new Map();
    const ids = new Set(S.sessions.map((s) => s.id));
    const roots = [];
    for (const s of S.sessions) {
      if (s.parent_id && ids.has(s.parent_id)) {
        if (!byParent.has(s.parent_id)) byParent.set(s.parent_id, []);
        byParent.get(s.parent_id).push(s);
      } else roots.push(s);
    }
    const out = [];
    for (const r of roots) {
      out.push([r, false]);
      for (const c of byParent.get(r.id) || []) out.push([c, true]);
    }
    return out;
  }

  function renderSessions() {
    const list = $("session-list");
    const sel = $("session-select");
    clear(list); clear(sel);
    const rows = orderedSessions();
    $("sessions-empty").hidden = rows.length > 0;
    for (const [s, child] of rows) {
      const dotCls = isLive(s) ? "dot dot--live" : (s.last_active && now() - s.last_active < 300 ? "dot dot--recent" : "dot");
      const meta = [
        h("span", null, s.source || "—"),
        h("span", null, fmtAgo(s.last_active || s.started_at)),
        h("span", null, (s.spans || 0) + " tools"),
      ];
      if (s.findings) meta.push(h("span", { class: "f" }, s.findings + " hallazgo" + (s.findings > 1 ? "s" : "")));
      if (s.errors) meta.push(h("span", { class: "e" }, s.errors + " ✗"));
      list.append(h("li", null, h("button", {
        class: "sess" + (child ? " sess--child" : ""), type: "button",
        "aria-current": s.id === S.sid ? "true" : "false",
        title: s.id, onclick: () => { $("follow-active").checked = false; selectSession(s.id); },
      }, h("span", { class: "sess__title" }, h("i", { class: dotCls }), h("span", null, sessionLabel(s))),
        h("span", { class: "sess__meta" }, meta))));
      sel.append(h("option", { value: s.id, selected: s.id === S.sid }, (child ? "↳ " : "") + sessionLabel(s)));
    }
  }
  $("session-select").addEventListener("change", (e) => {
    $("follow-active").checked = false;
    selectSession(e.target.value);
  });
  $("follow-active").addEventListener("change", () => { if ($("follow-active").checked) followActive(); });

  function followActive() {
    if (!S.sessions.length) return;
    const score = (s) => ((s.running || 0) > 0 ? 1e12 : 0) + (s.last_active || s.started_at || 0);
    const best = S.sessions.slice().sort((a, b) => score(b) - score(a))[0];
    if (best && best.id !== S.sid) selectSession(best.id);
  }

  async function loadSessions() {
    try {
      const doc = await api("/api/sessions?limit=200");
      S.sessions = doc.data || [];
      if (S.sid) S.session = S.sessions.find((s) => s.id === S.sid) || S.session;
      renderSessions();
      renderStrip();
      if ($("follow-active").checked || !S.sid) followActive();
      updateLive();
    } catch (_) { /* el pill de Hermes refleja el fallo */ }
  }
  const refreshSessionsSoon = throttle(loadSessions, 1500);

  // ───────────────────────────────────────────────────────── franja de sesión
  function currentOoda() {
    for (let i = S.events.length - 1; i >= 0; i--) if (S.events[i].kind === "ooda") return S.events[i];
    return null;
  }

  function renderStrip() {
    const s = S.session;
    $("session-strip").hidden = !s;
    if (!s) return;
    const o = currentOoda();
    const badge = $("strip-phase");
    badge.dataset.phase = o ? o.phase : (s.last_phase || "");
    badge.textContent = o ? o.phase + " · " + o.step : (s.last_phase ? s.last_phase + " · " + (s.last_step || "?") : "SIN FASE");
    $("strip-title").textContent = sessionLabel(s);
    const meta = $("strip-meta");
    clear(meta);
    const end = s.ended_at || s.last_active;
    const items = [
      ["Modelo", s.model ? String(s.model).split("/").pop() : "—"],
      ["Origen", s.source || "—"],
      ["Inicio", fmtDateTime(s.started_at)],
      ["Duración", s.started_at && end ? fmtDur(end - s.started_at) : "—"],
      ["Tokens", fmtInt(s.input_tokens) + " / " + fmtInt(s.output_tokens)],
      ["Coste", s.cost_usd != null ? "$" + Number(s.cost_usd).toFixed(4) : "—"],
    ];
    for (const [k, v] of items) meta.append(h("div", null, h("dt", null, k), h("dd", null, v)));
  }

  // ───────────────────────────────────────────────────────── selección de sesión
  async function selectSession(sid) {
    if (!sid) return;
    S.sid = sid;
    S.session = S.sessions.find((s) => s.id === sid) || null;
    S.events = []; S.lastSeq = 0; S.calls = new Map(); S.trace = null; S.traceSelected = null; S.traceZoom = null; S.childTraces = {}; S.graphView = null; S.graphSel = null; S.graphOpen = new Set(); S.toolSelected = null;
    S.loading = true; S.pending = [];
    renderSessions(); renderStrip();
    clear($("term"));
    $("term").append(h("div", { class: "term__empty" }, "Cargando sesión…"));
    try {
      const doc = await api("/api/sessions/" + encodeURIComponent(sid) + "/events?tail=1200");
      if (S.sid !== sid) return;
      S.events = doc.data || [];
      S.lastSeq = S.events.length ? S.events[S.events.length - 1].seq : 0;
      for (const ev of S.pending) if (ev.seq > S.lastSeq) { S.events.push(ev); S.lastSeq = ev.seq; }
    } catch (e) {
      clear($("term"));
      $("term").append(h("div", { class: "term__empty" }, "No se pudo cargar la sesión: " + e));
      return;
    } finally {
      S.loading = false; S.pending = [];
    }
    renderTerminal();
    renderStrip();
    if (S.view === "copilot") renderCopilot();
    if (S.view === "traces") loadTrace();
    if (S.view === "pocs") renderPocList();
    if (S.view === "pantallas") { renderPantActions(); renderStage(); }
  }

  // ───────────────────────────────────────────────────────── terminal
  const term = $("term");
  let termFollow = true;
  let termUnseen = 0;            // eventos llegados con el autoscroll en pausa
  const termTools = new Set();   // tools vistas en la sesión (desplegable de filtro)
  const tSearch = $("t-search"), tTool = $("t-tool");

  function applyTermFilters() {
    term.classList.toggle("hide-reasoning", !$("t-reasoning").checked);
    term.classList.toggle("hide-output", !$("t-output").checked);
    term.classList.toggle("hide-chat", !$("t-chat").checked);
  }
  ["t-reasoning", "t-output", "t-chat"].forEach((id) => $(id).addEventListener("change", applyTermFilters));

  // ── seguir el directo / volver al directo
  function updateLiveBtn() {
    const btn = $("t-live");
    btn.hidden = termFollow;
    btn.classList.toggle("has-new", termUnseen > 0);
    btn.textContent = termUnseen
      ? "↓ en vivo · " + termUnseen + (termUnseen === 1 ? " nuevo" : " nuevos")
      : "↓ volver al directo";
  }
  function setFollow(on) {
    termFollow = on;
    $("t-follow").checked = on;
    if (on) termUnseen = 0;
    updateLiveBtn();
  }
  $("t-follow").addEventListener("change", () => { setFollow($("t-follow").checked); scrollTermSoon(true); });
  $("t-live").addEventListener("click", () => { setFollow(true); scrollTermSoon(true); term.focus({ preventScroll: true }); });
  term.addEventListener("scroll", () => {
    const atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
    if (!atBottom && termFollow) setFollow(false);
    else if (atBottom && !termFollow) setFollow(true);
  });

  let scrollQueued = false;
  function scrollTermSoon(force) {
    if (!(termFollow || force) || scrollQueued) return;
    scrollQueued = true;
    requestAnimationFrame(() => { scrollQueued = false; if (termFollow || force) term.scrollTop = term.scrollHeight; });
  }

  function toggleOpen(el) { el.classList.toggle("is-open"); }

  function statusText(call) {
    if (!call.result) return { cls: "s s--run", text: "● " + fmtDur(now() - (call.ev.ts || now())), running: true };
    const dur = call.result.ts && call.ev.ts ? call.result.ts - call.ev.ts : null;
    return call.result.error
      ? { cls: "s s--err", text: "✗ " + fmtDur(dur) }
      : { cls: "s s--ok", text: "✓ " + fmtDur(dur) };
  }

  // ── salidas JSON como fichas
  const ST_OK = ["recorded", "done", "ok", "success", "succeeded", "completed", "accepted", "found", "saved"];
  const ST_ERR = ["error", "failed", "failure", "rejected", "denied", "invalid", "timeout", "blocked"];
  const ST_RUN = ["running", "pending", "started", "queued", "in_progress"];
  const JSON_KEY_ORDER = ["error", "message", "reason", "scope_violation", "returncode", "exit_code", "title", "id", "state", "url", "target", "count", "total"];

  function jsonState(d) {
    const st = String(d.status || "").toLowerCase();
    if (ST_ERR.includes(st) || d.isError === true || (!st && d.error)) return "err";
    if (ST_RUN.includes(st)) return "run";
    if (ST_OK.includes(st)) return "ok";
    return "info";
  }
  function isTextOutput(d) {
    return typeof d.output === "string" || ["stdout", "stderr"].some((k) => typeof d[k] === "string" && d[k]);
  }
  // Escalares de primer nivel y de un nivel anidado (finding.title…), los importantes primero.
  function jsonKeyFields(d) {
    const out = [];
    const push = (k, v) => { if (v !== null && v !== undefined && v !== "" && typeof v !== "object") out.push([k, v]); };
    for (const [k, v] of Object.entries(d)) {
      if (k === "status") continue;
      if (Array.isArray(v)) out.push([k, v.length + (v.length === 1 ? " elemento" : " elementos")]);
      else if (v && typeof v === "object") { for (const [k2, v2] of Object.entries(v)) push(k + "." + k2, v2); }
      else push(k, v);
    }
    const rank = (k) => { const i = JSON_KEY_ORDER.indexOf(k.split(".").pop()); return i < 0 ? 99 : i; };
    return out.map((f, i) => [f, i]).sort((a, b) => rank(a[0][0]) - rank(b[0][0]) || a[1] - b[1]).map((x) => x[0]);
  }
  function jsonCard(ev, d) {
    const kind = ev.error ? "err" : jsonState(d);
    const label = d.status != null ? String(d.status) : (kind === "err" ? "error" : "resultado");
    const fields = jsonKeyFields(d);
    const shown = fields.slice(0, 6);
    const extra = fields.length - shown.length;
    const card = h("div", { class: "out out--card k-output" + (kind === "err" ? " out--err" : ""), "data-st": kind });
    const btnLabel = () => (raw.hidden ? "ver JSON" + (extra > 0 ? " · +" + extra + " campos" : "") : "ocultar JSON");
    const raw = h("pre", { class: "jc__raw" }, JSON.stringify(d, null, 2));
    raw.hidden = true;
    const btn = h("button", { class: "linkbtn jc__toggle", type: "button", "aria-expanded": "false" });
    btn.textContent = btnLabel();
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      raw.hidden = !raw.hidden;
      btn.setAttribute("aria-expanded", String(!raw.hidden));
      btn.textContent = btnLabel();
    });
    card.append(h("div", { class: "jc__head" }, h("span", { class: "jc__st", "data-st": kind }, label), btn));
    if (shown.length) {
      const dl = h("dl", { class: "jc__fields" });
      for (const [k, v] of shown) {
        const scope = k === "scope_violation";
        const bad = /(^|\.)(error|reason)$/.test(k) || (scope && v === true) || (/(^|\.)(returncode|exit_code)$/.test(k) && Number(v) !== 0);
        const wide = /(^|\.)(error|reason|message)$/.test(k) || String(v).length > 48;
        dl.append(h("div", { class: "jc__f" + (bad ? " is-bad" : "") + (wide ? " is-wide" : "") },
          h("dt", null, scope ? "fuera de alcance" : k),
          h("dd", null, scope ? (v === true ? "sí" : "no") : oneLine(String(v), 240))));
      }
      card.append(dl);
    }
    card.append(raw);
    return card;
  }

  function outputBlock(ev) {
    const d = unwrap(ev.text);
    if (d && typeof d === "object" && !Array.isArray(d) && Object.keys(d).length && !isTextOutput(d)) return jsonCard(ev, d);
    const text = outputText(ev.text);
    const lines = text.replace(/\s+$/, "").split("\n");
    const maxLines = 14;
    const shown = lines.slice(0, maxLines).join("\n");
    const txt = h("span", { class: "out__txt" }, shown || "(sin salida)");
    const block = h("div", { class: "out k-output" + (ev.error ? " out--err" : "") }, txt);
    const hiddenLines = lines.length - maxLines;
    if (hiddenLines > 0 || ev.truncated) {
      const more = h("button", { class: "linkbtn out__more", type: "button" },
        hiddenLines > 0 ? "ver las " + lines.length + " líneas" : "ver salida completa");
      more.addEventListener("click", async () => {
        more.textContent = "cargando…";
        try {
          const full = await api("/api/events/" + ev.seq);
          txt.textContent = full.output != null ? full.output : outputText(full.text);
          more.remove();
          if (termFilterActive()) applySearch();
        } catch (e) { more.textContent = "error: " + e; }
      });
      block.append(more);
    }
    return block;
  }

  function noteTool(name) {
    if (!name || termTools.has(name)) return;
    termTools.add(name);
    tTool.append(h("option", { value: name }, name));
  }

  function appendTermEvent(ev) {
    const empty = term.querySelector(".term__empty");
    if (empty) empty.remove();
    let el = null;
    switch (ev.kind) {
      case "ooda": {
        el = h("div", { class: "ln ln--ooda" },
          h("span", { class: "phase-badge", "data-phase": ev.phase }, ev.phase + " · " + ev.step),
          h("span", { class: "d" }, ev.text || ""));
        // Datos antiguos (razonamiento emitido antes que su línea OODA): la cabecera va delante.
        const last = term.lastElementChild;
        if (last && last.classList.contains("ln--reasoning") && last.dataset.mid && last.dataset.mid === String(ev.message_id)) {
          last.before(el);
          afterAppend();
          return;
        }
        break;
      }
      case "user":
        el = h("div", { class: "ln ln--user" }, h("span", { class: "who" }, "operador ▸"),
          h("span", { class: "clamp clamp-6" }, ev.text || ""));
        el.addEventListener("click", () => toggleOpen(el));
        break;
      case "reasoning":
        el = h("div", { class: "ln ln--reasoning k-reasoning", "data-mid": ev.message_id != null ? String(ev.message_id) : null },
          h("span", { class: "clamp clamp-3" }, "∴ " + (ev.text || "")));
        el.addEventListener("click", () => toggleOpen(el));
        break;
      case "assistant": {
        const body = String(ev.text || "").split("\n").filter((l) => !OODA_LINE.test(l)).join("\n").trim();
        if (!body) return;
        el = h("div", { class: "ln ln--assistant k-chat" }, h("span", { class: "clamp clamp-6" }, body));
        el.addEventListener("click", () => toggleOpen(el));
        break;
      }
      case "tool.call": {
        const name = ev.tool_display || ev.tool || "?";
        const call = { ev, result: null, statusEl: null, anchor: null, line: null };
        const st = statusText(call);
        call.statusEl = h("span", { class: st.cls }, st.text);
        el = h("div", { class: "ln ln--call", "data-g": ev.call_id, "data-tool": name },
          h("span", { class: "p" }, "$"),
          h("span", { class: "t cat", "data-cat": ev.category || "tool" }, name),
          h("span", { class: "c" }, ev.summary || ""),
          call.statusEl);
        call.anchor = el;
        call.line = el;
        noteTool(name);
        const prev = S.calls.get(ev.call_id);
        if (prev && prev.result) { call.result = prev.result; }
        S.calls.set(ev.call_id, call);
        if (call.result) { const s2 = statusText(call); call.statusEl.className = s2.cls; call.statusEl.textContent = s2.text; }
        else el.classList.add("is-running");
        break;
      }
      case "tool.result": {
        const call = S.calls.get(ev.call_id);
        const block = outputBlock(ev);
        const name = (call && call.ev && (call.ev.tool_display || call.ev.tool)) || ev.tool_display || ev.tool || "";
        block.dataset.g = ev.call_id || "";
        if (name) block.dataset.tool = name;
        if (call && call.anchor) {
          call.result = ev;
          const st = statusText(call);
          call.statusEl.className = st.cls; call.statusEl.textContent = st.text;
          if (call.line) call.line.classList.remove("is-running");
          call.anchor.after(block);
          call.anchor = block;
          afterAppend();
          return;
        }
        S.calls.set(ev.call_id, { ev: { ts: null }, result: ev, statusEl: h("span"), anchor: null });
        el = block;
        break;
      }
      default:
        return;
    }
    term.append(el);
    afterAppend();
  }

  function afterAppend() {
    capTerm();
    if (termFilterActive()) applySearchSoon();
    if (!termFollow && !termBulk) { termUnseen++; updateLiveBtn(); }
    scrollTermSoon();
  }

  function capTerm() {
    if (term.childElementCount > 3000) {
      for (let i = 0; i < 500 && term.firstChild; i++) term.removeChild(term.firstChild);
    }
  }

  let termBulk = false;  // repintado completo: no cuenta como "nuevos"
  function renderTerminal() {
    clear(term);
    S.calls = new Map();
    termTools.clear();
    while (tTool.options.length > 1) tTool.remove(1);
    if (!S.events.length) {
      term.append(h("div", { class: "term__empty" }, "Esta sesión aún no tiene actividad."));
    }
    termBulk = true;
    for (const ev of S.events) appendTermEvent(ev);
    termBulk = false;
    if (tTool.value && !termTools.has(tTool.value)) tTool.value = "";
    applyTermFilters();
    if (termFilterActive()) applySearch(); else $("t-count").textContent = S.events.length + " eventos";
    setFollow(true);
    scrollTermSoon(true);
  }

  // ── buscar y filtrar por tool (resaltado con nodos de texto, nunca innerHTML)
  function termFilterActive() { return !!(tSearch.value.trim() || tTool.value); }
  function clearMarks() {
    term.querySelectorAll("mark.hl").forEach((m) => {
      const p = m.parentNode;
      p.replaceChild(document.createTextNode(m.textContent), m);
      p.normalize();
    });
  }
  function markText(el, q, budget) {
    const walker = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, {
      acceptNode: (n) => (n.parentElement && n.parentElement.closest("button, pre[hidden]") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    let n = 0;
    for (const node of nodes) {
      if (n >= budget) break;
      const text = node.nodeValue, low = text.toLowerCase();
      let i = low.indexOf(q);
      if (i < 0) continue;
      const frag = document.createDocumentFragment();
      let last = 0;
      while (i >= 0 && n < budget) {
        frag.append(text.slice(last, i), h("mark", { class: "hl" }, text.slice(i, i + q.length)));
        last = i + q.length; n++;
        i = low.indexOf(q, last);
      }
      frag.append(text.slice(last));
      node.parentNode.replaceChild(frag, node);
    }
    return n;
  }
  function applySearch() {
    clearMarks();
    const q = tSearch.value.trim().toLowerCase();
    const tool = tTool.value;
    const kids = [...term.children];
    const active = !!(q || tool);
    term.classList.toggle("is-searching", active);
    if (!active) {
      kids.forEach((k) => k.classList.remove("is-out"));
      $("t-count").textContent = S.events.length + " eventos";
      return;
    }
    const matches = (el) => !q || el.textContent.toLowerCase().includes(q);
    // Una tool-call y su salida van juntas: el grupo se ve si cualquiera de las dos coincide.
    const groupHit = new Map();
    for (const el of kids) {
      const g = el.dataset.g;
      if (g === undefined) continue;
      const hit = (!tool || el.dataset.tool === tool) && matches(el);
      groupHit.set(g, groupHit.get(g) || hit);
    }
    let hits = 0, budget = 400;
    for (const el of kids) {
      if (el.classList.contains("ln--ooda")) continue;
      const show = el.dataset.g !== undefined ? groupHit.get(el.dataset.g) : (!tool && matches(el));
      el.classList.toggle("is-out", !show);
      if (show) { hits++; if (q && budget > 0) budget -= markText(el, q, budget); }
    }
    // Cabeceras OODA: visibles si su tramo conserva algo, o si la propia cabecera coincide.
    let header = null, any = false;
    const close = () => {
      if (!header) return;
      const own = !tool && q && matches(header);
      header.classList.toggle("is-out", !(any || own));
      if ((any || own) && q && budget > 0) budget -= markText(header, q, budget);
    };
    for (const el of kids) {
      if (el.classList.contains("ln--ooda")) { close(); header = el; any = false; continue; }
      if (!el.classList.contains("is-out")) any = true;
    }
    close();
    const cnt = $("t-count");
    cnt.textContent = hits ? hits + " de " + S.events.length : "sin coincidencias";
    cnt.title = hits ? hits + (hits === 1 ? " línea coincide" : " líneas coinciden") + " (de " + S.events.length + " eventos)" : "";
  }
  const applySearchSoon = throttle(applySearch, 250);
  tSearch.addEventListener("input", applySearchSoon);
  tSearch.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { e.stopPropagation(); tSearch.value = ""; applySearch(); tSearch.blur(); }
    if (e.key === "Enter") { const first = term.querySelector("mark.hl"); if (first) first.scrollIntoView({ block: "center" }); setFollow(false); }
  });
  tTool.addEventListener("change", () => { applySearch(); scrollTermSoon(true); });
  document.addEventListener("keydown", (e) => {
    if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey || S.view !== "terminal") return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName))) return;
    e.preventDefault();
    tSearch.focus();
    tSearch.select();
  });

  // Temporizadores de tools en curso (terminal + copilot).
  setInterval(() => {
    for (const call of S.calls.values()) {
      if (call.result || !call.statusEl || !call.ev.ts) continue;
      call.statusEl.textContent = "● " + fmtDur(now() - call.ev.ts);
    }
    document.querySelectorAll("[data-since]").forEach((el) => {
      el.textContent = fmtDur(now() - Number(el.dataset.since));
    });
    document.querySelectorAll(".wf-bar[data-status='running']").forEach(() => markTraceDirty());
  }, 500);

  // ───────────────────────────────────────────────────────── copilot
  let copilotDirty = false;
  function markCopilotDirty() {
    if (S.view !== "copilot") { copilotDirty = true; return; }
    if (copilotDirty) return;
    copilotDirty = true;
    requestAnimationFrame(() => { if (copilotDirty) renderCopilot(); });
  }

  function feedEmpty(list, text) { list.append(h("li", { class: "feed__empty" }, text)); }

  function renderCopilot() {
    copilotDirty = false;
    const o = currentOoda();
    const badge = $("now-phase");
    badge.dataset.phase = o ? o.phase : "";
    badge.textContent = o ? o.phase : "—";
    $("now-step").textContent = o ? "step " + o.step + " · " + fmtAgo(o.ts) : "";
    $("now-desc").textContent = o ? o.text : (S.sid ? "El agente aún no ha emitido su línea de estado OODA." : "Esperando actividad del agente…");

    const running = $("now-running");
    clear(running);
    const live = [...S.calls.values()].filter((c) => !c.result && c.ev.ts);
    if (!live.length) running.append(h("li", { class: "running--idle" }, "Nada en curso"));
    for (const c of live) {
      running.append(h("li", null,
        h("span", { class: "el", "data-since": c.ev.ts }, fmtDur(now() - c.ev.ts)),
        h("span", { class: "t cat", "data-cat": c.ev.category }, c.ev.tool_display || c.ev.tool),
        h("span", { class: "c", title: c.ev.summary || "" }, c.ev.summary || "")));
    }
    let thought = null;
    for (let i = S.events.length - 1; i >= 0; i--) if (S.events[i].kind === "reasoning") { thought = S.events[i]; break; }
    $("now-thought").textContent = thought ? oneLine(thought.text, 420) : "—";

    // Herramientas
    const tools = $("cp-tools");
    clear(tools);
    const calls = S.events.filter((e) => e.kind === "tool.call");
    $("cp-tools-meta").textContent = calls.length + " llamadas";
    if (!calls.length) feedEmpty(tools, "Sin tool-calls todavía.");
    for (const ev of calls.slice(-80).reverse()) {
      const c = S.calls.get(ev.call_id) || { ev, result: null };
      const st = statusText(c);
      tools.append(h("li", null,
        h("span", { class: "tm" }, fmtTime(ev.ts)),
        h("span", { class: "bd" }, h("span", { class: "t cat", "data-cat": ev.category }, ev.tool_display || ev.tool),
          h("span", { class: "c" }, oneLine(ev.summary, 220))),
        st.running ? h("span", { class: "st " + st.cls, "data-since": ev.ts }, fmtDur(now() - ev.ts))
          : h("span", { class: "st " + st.cls }, st.text)));
    }

    // Navegador
    const br = $("cp-browser");
    clear(br);
    const bcalls = calls.filter((e) => e.category === "browser");
    if (!bcalls.length) feedEmpty(br, "El agente no ha usado el navegador en esta sesión.");
    for (const ev of bcalls.slice(-60).reverse()) {
      const c = S.calls.get(ev.call_id);
      const action = String(ev.tool_display || ev.tool || "").replace(/^browser_/, "");
      let res = "";
      if (c && c.result) {
        const out = outputText(c.result.text);
        const url = out.match(/Page URL:\s*(\S+)/);
        const title = out.match(/Page Title:\s*(.+)/);
        res = url ? url[1] + (title ? " · " + title[1] : "") : oneLine(out, 120);
      }
      br.append(h("li", null,
        h("span", { class: "tm" }, fmtTime(ev.ts)),
        h("span", { class: "bd" }, h("span", { class: "t cat", "data-cat": "browser" }, action),
          h("span", { class: "c" }, oneLine(ev.summary, 200)),
          res ? h("div", { class: "c muted" }, "→ " + res) : null),
        h("span", { class: "st " + statusText(c || { ev, result: null }).cls }, c && c.result ? (c.result.error ? "✗" : "✓") : "●")));
    }

    // Tráfico web (global)
    renderWeb();

    // Hallazgos
    const fl = $("cp-findings");
    clear(fl);
    const finds = calls.filter(isFinding);
    if (!finds.length) feedEmpty(fl, "Sin hallazgos registrados en esta sesión.");
    for (const ev of finds.slice().reverse()) {
      const a = ev.args || {};
      const c = S.calls.get(ev.call_id);
      // El veredicto del store manda: un "confirmed" rechazado NO se pinta como confirmado.
      let verdict = "registrando…", vcls = "st", rejected = false, why = "";
      if (c && c.result) {
        const d = unwrap(c.result.text);
        const ok = d && d.status === "recorded";
        rejected = !ok;
        verdict = ok ? "registrado" : "rechazado";
        vcls = "st " + (ok ? "s--ok" : "s--err");
        if (rejected) why = (d && (d.error || d.message)) || "";
      }
      const chipCls = "chip chip--" + (rejected ? "rejected" : (a.state || "hypothesis"));
      const chipTxt = rejected ? "rechazado" : (a.state || "?");
      fl.append(h("li", null,
        h("span", { class: "tm" }, fmtTime(ev.ts)),
        h("span", { class: "bd" }, h("span", { class: chipCls }, chipTxt), " ",
          h("span", { class: "c" }, a.title || "(sin título)"),
          rejected && a.state ? h("span", { class: "c muted" }, " · pedía " + a.state) : null,
          a.target ? h("div", { class: "c muted" }, a.target) : null,
          why ? h("div", { class: "c s--err" }, oneLine(why, 160)) : null),
        h("span", { class: vcls }, verdict)));
    }
  }

  function renderWeb() {
    const body = $("cp-web");
    clear(body);
    const c = (S.status && S.status.caido) || {};
    $("cp-web-meta").textContent = !c.enabled ? "feed desactivado"
      : c.ok ? S.web.length + " recientes · " + fmtInt(c.requests) + " en Caido" : "Caido no responde: " + (c.last_error || "—");
    if (!S.web.length) {
      body.append(h("tr", null, h("td", { colspan: 6, class: "muted" },
        "Sin tráfico capturado. Llega aquí todo lo que pasa por el proxy de Caido (caido_request, y kali_run con CAIDO_PROXY_CAPTURE=1).")));
      return;
    }
    for (const ev of S.web.slice(-200).reverse()) {
      const x = ev.extra || {};
      const code = x.status;
      const cc = code == null ? "x" : String(code)[0];
      body.append(h("tr", null,
        h("td", null, fmtTime(ev.ts)),
        h("td", null, x.method || "?"),
        h("td", { class: "code code--" + cc }, code == null ? "…" : code),
        h("td", { class: "url" }, x.url || ""),
        h("td", { class: "num" }, x.roundtrip_ms != null ? x.roundtrip_ms : "—"),
        h("td", { class: "num" }, fmtBytes(x.resp_length))));
    }
  }

  async function loadWebTail() {
    try {
      const doc = await api("/api/web?tail=200");
      S.web = doc.data || [];
      if (S.view === "copilot") renderWeb();
    } catch (_) { /* opcional */ }
  }

  // ───────────────────────────────────────────────────────── trazas
  let traceDirty = false;
  const traceRefresh = throttle(() => { if (S.view === "traces") loadTrace(); }, 2000);
  function markTraceDirty() { traceDirty = true; if (S.view === "traces") traceRefresh(); }

  async function loadTrace() {
    if (!S.sid) return;
    const sid = S.sid;
    try {
      const doc = await api("/api/sessions/" + encodeURIComponent(sid) + "/trace");
      if (S.sid !== sid) return;
      if (doc.now) skew = doc.now - Date.now() / 1000;
      // trazas de los subagentes (sesiones hijas) para sus nodos del grafo
      const kids = S.sessions.filter((s) => s.parent_id === sid).slice(0, 8);
      const docs = await Promise.all(kids.map((c) => api("/api/sessions/" + encodeURIComponent(c.id) + "/trace").catch(() => null)));
      if (S.sid !== sid) return;
      S.childTraces = {};
      kids.forEach((c, i) => { if (docs[i]) S.childTraces[c.id] = docs[i]; });
      S.trace = doc; traceDirty = false;
      renderTrace();
    } catch (e) {
      clear($("tr-waterfall"));
      $("tr-waterfall").append(h("p", { class: "empty" }, "No se pudo cargar la traza: " + e));
    }
  }

  function kpi(label, value, small, cls) {
    return h("div", { class: "kpi" + (cls ? " " + cls : "") }, h("dt", null, label), h("dd", null, value, small ? h("small", null, small) : null));
  }

  function niceStep(range) {
    const raw = range / 6;
    const steps = [0.1, 0.25, 0.5, 1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200];
    return steps.find((s) => s >= raw) || Math.ceil(raw / 3600) * 3600;
  }

  const PHASES = ["OBSERVE", "ORIENT", "DECIDE", "ACT", "REPORT"];
  const PH_SHORT = { OBSERVE: "OBS", ORIENT: "ORI", DECIDE: "DEC", ACT: "ACT", REPORT: "REP" };
  const pct = (v) => v + "%";
  const clamp = (v, lo, hi) => Math.min(Math.max(v, lo), hi);

  // Bandas OODA: de cada línea de estado a la siguiente (la última llega al final de la ventana).
  // Sin líneas OODA en el stream, se deducen de la fase/step con que vienen etiquetados los spans.
  function oodaBands(spans, t1) {
    let marks = S.events.filter((e) => e.kind === "ooda" && e.ts && e.phase)
      .map((e) => ({ ts: e.ts, phase: e.phase, step: e.step, text: e.text || "" }));
    if (!marks.length) {
      const seen = new Map();
      for (const sp of spans) {
        if (!sp.phase || !sp.started_at) continue;
        const key = sp.phase + "·" + sp.step;
        if (!seen.has(key)) seen.set(key, { ts: sp.started_at, phase: sp.phase, step: sp.step, text: "" });
      }
      marks = [...seen.values()];
    }
    marks.sort((a, b) => a.ts - b.ts);
    return marks.map((m, i) => ({ ...m, end: i + 1 < marks.length ? marks[i + 1].ts : t1 })).filter((b) => b.end > b.ts);
  }

  // Tiempo de reloj con al menos una tool corriendo (unión de intervalos: las paralelas no cuentan doble).
  function unionLength(intervals) {
    const xs = intervals.filter(([a, b]) => b > a).sort((p, q) => p[0] - q[0]);
    let total = 0, cs = null, ce = null;
    for (const [a, b] of xs) {
      if (ce === null || a > ce) { if (ce !== null) total += ce - cs; cs = a; ce = b; }
      else ce = Math.max(ce, b);
    }
    if (ce !== null) total += ce - cs;
    return total;
  }

  function traceModel() {
    const spans = (S.trace && S.trace.spans) || [];
    const nowS = now();
    const iv = spans.map((s) => {
      const a = s.started_at || s.ended_at || 0;
      return [a, s.ended_at || (s.status === "running" ? nowS : a)];
    });
    const oodaTs = S.events.filter((e) => e.kind === "ooda" && e.ts).map((e) => e.ts);
    let t0 = Infinity, t1 = 0;
    for (const [a, b] of iv) { if (a) t0 = Math.min(t0, a); t1 = Math.max(t1, a, b); }
    for (const t of oodaTs) { t0 = Math.min(t0, t); t1 = Math.max(t1, t); }
    const ok = isFinite(t0) && t1 >= t0;
    const wall = ok ? t1 - t0 : 0;
    return { spans, iv, t0: ok ? t0 : null, t1, wall, nowS, live: spans.some((s) => s.status === "running"),
             bands: ok ? oodaBands(spans, t1) : [] };
  }

  function renderTrace() {
    const doc = S.trace;
    if (!doc) return;
    if (S.wfDrag) { traceDirty = true; return; }  // no repintar a mitad de un arrastre de zoom
    const sum = doc.summary || {};
    const sess = doc.session || {};
    const m = traceModel();
    const execT = unionLength(m.iv);
    const thinkT = Math.max(m.wall - execT, 0);
    const share = (v) => (m.wall ? Math.round((v / m.wall) * 100) + "% de la ventana" : null);

    const k = $("tr-kpis");
    clear(k);
    k.append(
      kpi("Tool-calls", fmtInt(sum.spans || 0), sum.running ? sum.running + " en curso" : (sum.spans ? "todas cerradas" : null)),
      kpi("Ejecutando tools", fmtDur(execT), share(execT)),
      kpi("Pensando · LLM", fmtDur(thinkT), share(thinkT)),
      kpi("Errores", fmtInt(sum.errors || 0), sum.spans ? "de " + fmtInt(sum.spans) + " llamadas" : null, sum.errors ? "kpi--err" : null),
      kpi("Tokens", fmtInt(sess.input_tokens), "entrada · " + fmtInt(sess.output_tokens) + " salida"),
      kpi("Coste", sess.cost_usd != null ? "$" + Number(sess.cost_usd).toFixed(4) : "—", sess.model || null));

    renderSplit(m, execT, thinkT);

    const leg = $("tr-legend");
    clear(leg);
    const cats = [...new Set(m.spans.map((s) => s.category || "tool"))];
    for (const c of cats) leg.append(h("span", null, h("i", { class: "cat", "data-cat": c, style: { background: "var(--c)" } }), CAT_LABEL[c] || c));
    if (m.spans.some((s) => s.status === "error")) leg.append(h("span", null, h("i", { style: { background: "var(--err)" } }), "error"));
    if (m.live) leg.append(h("span", null, h("i", { class: "is-running" }), "en curso"));
    if (m.bands.length) leg.append(h("span", { class: "legend__sep" }, "fondo = fase OODA"));

    renderWaterfall(m);
    renderGraph(m);

    const tb = $("tr-tools");
    clear(tb);
    const tools = sum.tools || [];
    const toolSum = tools.reduce((a, t) => a + (t.total || 0), 0) || 1;
    for (const t of tools) {
      const w = ((t.total || 0) / toolSum) * 100;
      const sel = S.toolSelected === t.tool;
      const row = h("tr", { class: "row-sel" + (sel ? " is-sel" : ""), tabindex: 0, role: "button",
                             "aria-pressed": sel ? "true" : "false", "aria-label": "Ver a fondo " + t.tool },
        h("td", null, h("span", { class: "cat", "data-cat": t.category }, t.tool)),
        h("td", { class: "num" }, fmtInt(t.calls)),
        h("td", { class: "num" }, fmtDur(t.total)),
        h("td", { class: "num" }, fmtDur(t.avg)),
        h("td", { class: "num" }, fmtDur(t.max)),
        h("td", { class: "num" + (t.errors ? " s--err" : "") }, fmtInt(t.errors)),
        h("td", { class: "weight" }, h("div", { class: "bar" }, h("i", { class: "cat", "data-cat": t.category, style: { width: w + "%" } })),
          h("span", { class: "weight__pct" }, (w < 10 ? w.toFixed(1) : Math.round(w)) + "%")));
      const toggle = () => { S.toolSelected = S.toolSelected === t.tool ? null : t.tool; renderTrace(); };
      row.addEventListener("click", toggle);
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
      tb.append(row);
    }
    if (!tools.length) tb.append(h("tr", null, h("td", { colspan: 7, class: "muted" }, "—")));
    renderToolDetail(m);
    if (S.traceSelected) {
      const sp = m.spans.find((s) => s.call_id === S.traceSelected);
      if (sp && !$("tr-detail").hidden) renderTraceDetail(sp, true);
    }
  }

  // Barra apilada 100% + leyenda con valores (la identidad nunca va solo en el color).
  function splitBar(segs, total) {
    const live = segs.filter((s) => s.value > 0);
    const fmtShare = (v) => { const p = (v / total) * 100; return (p < 10 ? p.toFixed(1) : Math.round(p)) + "%"; };
    const bar = h("div", { class: "split__bar", role: "img",
      "aria-label": live.map((s) => s.label + " " + fmtDur(s.value) + " (" + fmtShare(s.value) + ")").join(", ") });
    const legend = h("ul", { class: "split__legend" });
    for (const s of live) {
      const seg = h("span", { class: "split__seg " + (s.cls || ""), "data-phase": s.phase || null, style: { flexGrow: String(s.value) } });
      seg.title = s.label + " · " + fmtDur(s.value) + " · " + fmtShare(s.value);
      bar.append(seg);
      legend.append(h("li", null, h("i", { class: "split__key " + (s.cls || ""), "data-phase": s.phase || null }),
        h("b", null, fmtDur(s.value)), h("span", null, s.label), h("small", null, fmtShare(s.value))));
    }
    return [bar, legend];
  }

  function renderSplit(m, execT, thinkT) {
    const box = $("tr-split");
    clear(box);
    if (!m.wall) { box.append(h("p", { class: "empty" }, "Sin actividad todavía.")); return; }
    box.append(h("div", { class: "split__row" }, h("span", { class: "split__label" }, "Agente"),
      ...splitBar([{ label: "ejecutando tools", value: execT, cls: "seg--exec" },
                   { label: "pensando / LLM", value: thinkT, cls: "seg--think" }], m.wall)));
    const per = {};
    for (const b of m.bands) per[b.phase] = (per[b.phase] || 0) + (b.end - b.ts);
    const phs = PHASES.filter((p) => per[p] > 0).map((p) => ({ label: p.toLowerCase(), value: per[p], phase: p }));
    const tot = phs.reduce((a, s) => a + s.value, 0);
    if (phs.length) {
      box.append(h("div", { class: "split__row" }, h("span", { class: "split__label" }, "Fases OODA"), ...splitBar(phs, tot)));
    }
  }

  const fmtOff = (s) => (s <= 0 ? "0" : "+" + fmtDur(s));

  function wfLine(label, content, cls) {
    return h("div", { class: "wf-line" + (cls ? " " + cls : "") }, h("span", { class: "wf-line__lab" }, label), content);
  }

  // Vista general de toda la sesión: arrastrar selecciona el tramo a ampliar; doble clic, ver todo.
  function wfOverview(m, full, va, vb) {
    const ov = h("div", { class: "wf-ov", title: "Arrastra para ampliar un tramo · doble clic para ver todo" });
    const OX = (t) => ((t - m.t0) / full) * 100;
    for (const b of m.bands) {
      ov.append(h("span", { class: "wf-ov__band", "data-phase": b.phase, style: { left: pct(OX(b.ts)), width: pct(Math.max(OX(b.end) - OX(b.ts), 0)) } }));
    }
    const n = m.spans.length, H = 24;
    const rowH = n ? clamp(H / n, 1.5, 4) : 2;
    m.spans.forEach((sp, i) => {
      const [a, b] = m.iv[i];
      ov.append(h("span", { class: "wf-ov__bar cat", "data-cat": sp.category, "data-status": sp.status,
        style: { left: pct(OX(a)), width: pct(Math.max(OX(b) - OX(a), 0.35)), top: (4 + (n > 1 ? (i * (H - rowH)) / (n - 1) : 0)) + "px", height: rowH + "px" } }));
    });
    const win = h("span", { class: "wf-ov__win", style: { left: pct((va / full) * 100), width: pct(((vb - va) / full) * 100) } });
    win.hidden = !S.traceZoom;
    ov.append(win);
    ov.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      e.preventDefault();
      const rect = ov.getBoundingClientRect();
      const fx = (cx) => clamp((cx - rect.left) / rect.width, 0, 1);
      const x0 = fx(e.clientX);
      S.wfDrag = true;
      try { ov.setPointerCapture(e.pointerId); } catch (_) { /* opcional */ }
      win.hidden = false; win.style.left = pct(x0 * 100); win.style.width = "0%";
      const move = (ev) => { const x1 = fx(ev.clientX); win.style.left = pct(Math.min(x0, x1) * 100); win.style.width = pct(Math.abs(x1 - x0) * 100); };
      const up = (ev) => {
        ov.removeEventListener("pointermove", move); ov.removeEventListener("pointerup", up); ov.removeEventListener("pointercancel", up);
        S.wfDrag = false;
        const x1 = fx(ev.clientX), a = Math.min(x0, x1), b = Math.max(x0, x1);
        if (b - a > 0.01) S.traceZoom = [a * full, b * full];
        renderTrace();
      };
      ov.addEventListener("pointermove", move); ov.addEventListener("pointerup", up); ov.addEventListener("pointercancel", up);
    });
    ov.addEventListener("dblclick", () => { S.traceZoom = null; renderTrace(); });
    return ov;
  }

  const wfTip = h("div", { class: "wf-tip", role: "tooltip" });
  wfTip.hidden = true;
  document.body.append(wfTip);

  function showWfTip(m, i, e) {
    const sp = m.spans[i], [a, b] = m.iv[i];
    const running = sp.status === "running", err = sp.status === "error";
    clear(wfTip);
    wfTip.append(
      h("div", { class: "wf-tip__val" }, running ? fmtDur(m.nowS - a) : fmtDur(sp.duration != null ? sp.duration : b - a),
        h("span", { class: running ? "s--run" : err ? "s--err" : "s--ok" }, running ? "● en curso" : err ? "✗ error" : "✓ ok")),
      h("div", { class: "wf-tip__tool" }, h("span", { class: "cat", "data-cat": sp.category }, sp.tool_display || sp.tool || "?"),
        sp.phase ? h("span", { class: "wf-ph", "data-phase": sp.phase }, (PH_SHORT[sp.phase] || sp.phase) + " · " + sp.step) : null),
      h("div", { class: "wf-tip__meta" }, "inicio " + fmtOff(a - m.t0) + " · " + fmtTime(a)),
      sp.summary ? h("div", { class: "wf-tip__sum" }, oneLine(sp.summary, 180)) : null);
    wfTip.hidden = false;
    const r = wfTip.getBoundingClientRect();
    let x = e.clientX + 16, y = e.clientY + 16;
    if (x + r.width > window.innerWidth - 8) x = e.clientX - r.width - 16;
    if (y + r.height > window.innerHeight - 8) y = e.clientY - r.height - 16;
    wfTip.style.left = Math.max(8, x) + "px";
    wfTip.style.top = Math.max(8, y) + "px";
  }

  let wfHoverFx = null;  // posición del cursor (0..1 de la pista): sobrevive al repintado periódico
  function renderWaterfall(m) {
    const wf = $("tr-waterfall");
    const keepScroll = wf.scrollTop;
    clear(wf);
    const full = Math.max(m.wall, 1);
    if (!m.spans.length && !m.bands.length) {
      wfTip.hidden = true;
      $("tr-range").textContent = "";
      $("tr-reset").hidden = true;
      wf.append(h("p", { class: "empty" }, "Sin tool-calls en esta sesión."));
      return;
    }
    let [va, vb] = S.traceZoom || [0, full];
    vb = Math.min(vb, full);
    if (vb - va < 0.2) { S.traceZoom = null; va = 0; vb = full; }
    const span = vb - va;
    const X = (t) => ((t - m.t0 - va) / span) * 100;
    $("tr-range").textContent = S.traceZoom
      ? "tramo " + fmtOff(va) + " → " + fmtOff(vb) + " de " + fmtDur(full)
      : "ventana " + fmtDur(full) + " · arrastra en la vista general para ampliar";
    $("tr-reset").hidden = !S.traceZoom;

    const step = niceStep(span);
    const tickTs = [];
    for (let t = Math.ceil(va / step - 1e-9) * step; t <= vb + 1e-9; t += step) tickTs.push(t);

    // ── cabecera fija: vista general · carril OODA · eje
    const head = h("div", { class: "wf-head" });
    head.append(wfLine("Vista general", wfOverview(m, full, va, vb)));
    if (m.bands.length) {
      const lane = h("div", { class: "wf-lane" });
      for (const b of m.bands) {
        const l = X(b.ts), r = X(b.end);
        if (r <= 0 || l >= 100) continue;
        const L = Math.max(l, 0), W = Math.min(r, 100) - L;
        const seg = h("span", { class: "wf-band", "data-phase": b.phase, style: { left: pct(L), width: pct(W) } },
          W > 5 ? (PH_SHORT[b.phase] || b.phase) + " " + (b.step != null ? b.step : "") : "");
        seg.title = b.phase + " · step " + b.step + (b.text ? " — " + b.text : "") + " · " + fmtDur(b.end - b.ts);
        lane.append(seg);
      }
      head.append(wfLine("Fases OODA", lane));
    }
    const ticks = h("div", { class: "wf-ticks" });
    for (const t of tickTs) {
      const x = ((t - va) / span) * 100;
      ticks.append(h("span", { class: x > 96 ? "is-end" : null, style: { left: pct(x) } }, t === 0 ? "0" : fmtDur(t)));
    }
    const curLab = h("span", { class: "wf-curlab" });
    curLab.hidden = true;
    ticks.append(curLab);
    head.append(wfLine("", ticks, "wf-line--axis"));
    wf.append(head);

    // ── cuerpo: fondo (fases, rejilla, ahora, cursor) + filas
    const body = h("div", { class: "wf-body" });
    const grid = h("div", { class: "wf-grid", "aria-hidden": "true" });
    for (const b of m.bands) {
      const l = X(b.ts), r = X(b.end);
      if (r <= 0 || l >= 100) continue;
      const L = Math.max(l, 0);
      grid.append(h("span", { class: "wf-gband", "data-phase": b.phase, style: { left: pct(L), width: pct(Math.min(r, 100) - L) } }));
    }
    for (const t of tickTs) grid.append(h("span", { class: "wf-gline", style: { left: pct(((t - va) / span) * 100) } }));
    if (m.live) {
      const nx = X(m.nowS);
      if (nx >= 0 && nx <= 100) grid.append(h("span", { class: "wf-now", style: { left: pct(nx) } }));
    }
    const cursor = h("span", { class: "wf-cursor" });
    cursor.hidden = true;
    grid.append(cursor);
    const placeCursor = (fx) => {
      const on = fx !== null && fx >= 0 && fx <= 1;
      cursor.hidden = !on; curLab.hidden = !on;
      if (!on) return;
      cursor.style.left = pct(fx * 100); curLab.style.left = pct(fx * 100); curLab.textContent = fmtOff(va + fx * span);
    };
    body.append(grid);

    m.spans.forEach((sp, i) => {
      const [a, b] = m.iv[i];
      const l = X(a), r = X(b);
      const out = r < 0 || l > 100;
      const L = clamp(l, 0, 100), R = clamp(r, 0, 100);
      const W = Math.max(R - L, 0.3);
      const running = sp.status === "running";
      const durLabel = running ? "● " + fmtDur(m.nowS - a) : fmtDur(sp.duration != null ? sp.duration : b - a);
      let durCls = "wf-dur", durPos;
      if (R < 80) durPos = { left: "calc(" + R + "% + 6px)" };
      else if (L > 20) durPos = { right: "calc(" + (100 - L) + "% + 6px)" };
      else { durPos = { left: "calc(" + L + "% + 8px)" }; durCls += " wf-dur--in"; }
      const barCls = "wf-bar cat" + (l < 0 ? " is-clip-l" : "") + (r > 100 ? " is-clip-r" : "");
      const row = h("div", { class: "wf-row" + (out ? " wf-row--out" : ""), role: "button", tabindex: "0", "data-i": i,
                              "aria-current": S.traceSelected === sp.call_id ? "true" : "false" },
        h("div", { class: "wf-label" },
          h("span", { class: "wf-ph", "data-phase": sp.phase || "" }, sp.phase ? (PH_SHORT[sp.phase] || sp.phase) + " " + (sp.step != null ? sp.step : "") : "—"),
          h("span", { class: "t cat", "data-cat": sp.category }, sp.tool_display || sp.tool || "?"),
          h("span", { class: "c" }, sp.summary || "")),
        h("div", { class: "wf-track" },
          out ? null : h("span", { class: barCls, "data-cat": sp.category, "data-status": sp.status, style: { left: pct(L), width: pct(W) } }),
          out ? null : h("span", { class: durCls, style: durPos }, durLabel)));
      const open = () => {
        S.traceSelected = sp.call_id; renderTraceDetail(sp);
        body.querySelectorAll(".wf-row").forEach((x) => x.setAttribute("aria-current", "false"));
        row.setAttribute("aria-current", "true");
      };
      row.addEventListener("click", open);
      row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } });
      row.addEventListener("focus", () => { const r2 = row.getBoundingClientRect(); showWfTip(m, i, { clientX: r2.left + r2.width * 0.4, clientY: r2.bottom }); });
      row.addEventListener("blur", () => { wfTip.hidden = true; });
      body.append(row);
    });

    // cursor de tiempo + tooltip de la fila bajo el ratón
    body.addEventListener("pointermove", (e) => {
      const track = body.querySelector(".wf-track");
      if (!track) return;
      const tr = track.getBoundingClientRect();
      wfHoverFx = (e.clientX - tr.left) / tr.width;
      placeCursor(wfHoverFx);
      const row = e.target.closest(".wf-row");
      if (row) showWfTip(m, Number(row.dataset.i), e); else wfTip.hidden = true;
    });
    body.addEventListener("pointerleave", () => { wfHoverFx = null; placeCursor(null); wfTip.hidden = true; });
    wf.append(body);
    placeCursor(wfHoverFx);
    wf.scrollTop = keepScroll;
  }
  $("tr-reset").addEventListener("click", () => { S.traceZoom = null; renderTrace(); });

  // ───────────────────────────────────────────────────────── grafo en vivo
  // Objetivos ← Hermes (anillo OODA) → actores (familias de tools + subagentes). Solo datos reales:
  // spans de la traza, args de los tool.call y las sesiones hijas. SVG a mano (CSP: sin librerías).
  const SVGNS = "http://www.w3.org/2000/svg";
  function sv(tag, attrs, ...children) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v !== null && v !== undefined && v !== false) el.setAttribute(k, String(v));
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const FAM_ORDER = ["shell", "browser", "web", "recon", "finding", "tracking", "subagent", "tool"];
  const FAM_NAME = { shell: "Shell · Kali", browser: "Navegador", web: "Caido", recon: "Recon", finding: "Hallazgos",
                     tracking: "Tracking", subagent: "Delegación", tool: "Otras tools" };
  const HOST_URL = /\bhttps?:\/\/([a-z0-9.-]+)/gi;
  const HOST_IP = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const HOST_BARE = /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i;
  // Fase continua de las animaciones aunque el SVG se rehaga cada pocos segundos.
  const animDelay = (period) => "-" + ((Date.now() % (period * 1000)) / 1000).toFixed(3) + "s";

  function hostsOf(args, summary) {
    const out = new Set();
    const scan = (v, depth) => {
      if (v == null || depth > 3) return;
      if (typeof v === "string") {
        for (const mm of v.matchAll(HOST_URL)) out.add(mm[1].toLowerCase());
        for (const mm of v.matchAll(HOST_IP)) out.add(mm[0]);
      } else if (Array.isArray(v)) v.forEach((x) => scan(x, depth + 1));
      else if (typeof v === "object") Object.values(v).forEach((x) => scan(x, depth + 1));
    };
    if (args) {
      for (const k of ["targets", "target", "domain", "host"]) {
        const v = args[k];
        for (const x of (Array.isArray(v) ? v : v ? [v] : [])) {
          const s = String(x).trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/:]/)[0];
          if (HOST_BARE.test(s) || /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s)) out.add(s);
        }
      }
      scan(args, 0);
    }
    if (!out.size && summary) scan(summary, 0);
    return [...out];
  }

  function graphModel(m) {
    const callEv = new Map();
    const resEv = new Map();
    for (const e of S.events) {
      if (e.kind === "tool.call" && e.call_id) callEv.set(e.call_id, e);
      else if (e.kind === "tool.result" && e.call_id) resEv.set(e.call_id, e);
    }
    const children = S.sessions.filter((s) => s.parent_id === S.sid);
    const fams = new Map();
    const targets = new Map();
    let hyp = 0, conf = 0;
    const touch = (host) => {
      if (!targets.has(host)) targets.set(host, { host, calls: 0, running: 0, ok: 0, bad: 0, last: 0, items: [], findings: [] });
      return targets.get(host);
    };
    m.spans.forEach((sp, i) => {
      const cat = sp.category || "tool";
      const [a, b] = m.iv[i];
      const ev = callEv.get(sp.call_id);
      const args = (ev && ev.args) || {};
      if (!(cat === "subagent" && children.length)) {
        if (!fams.has(cat)) fams.set(cat, { kind: "fam", cat, items: [], running: [], errors: 0, total: 0, tools: new Map(), last: 0 });
        const f = fams.get(cat);
        f.items.push({ sp, a, b });
        if (sp.status === "running") f.running.push({ sp, a });
        if (sp.status === "error") f.errors += 1;
        f.total += Math.max(b - a, 0);
        const tn = sp.tool_display || sp.tool || "?";
        f.tools.set(tn, (f.tools.get(tn) || 0) + 1);
        f.last = Math.max(f.last, b);
      }
      for (const host of hostsOf(args, sp.summary)) {
        const t = touch(host);
        t.calls += 1; t.last = Math.max(t.last, b); t.items.push({ sp, a, b });
        if (sp.status === "running") t.running += 1;
      }
      if (cat === "finding" && /record_finding/.test(sp.tool || "")) {
        hyp += 1;
        const res = resEv.get(sp.call_id);
        const recorded = res && !res.error && /"recorded"/.test(res.text || "");
        if (recorded && args.state === "confirmed") conf += 1;
        for (const host of hostsOf({ target: args.target }, "")) {
          const t = touch(host);
          if (res) { if (recorded) t.ok += 1; else t.bad += 1; }
          t.findings.push({ title: args.title || "(sin título)", state: args.state, recorded: !!recorded, done: !!res,
                            why: res && !recorded ? oneLine(res.summary || res.text || "", 140) : "" });
        }
      }
    });
    const actors = FAM_ORDER.filter((c) => fams.has(c)).map((c) => fams.get(c));
    for (const c of children) {
      const tr = S.childTraces[c.id];
      const spans = (tr && tr.spans) || [];
      const nowS = m.nowS;
      actors.push({
        kind: "sub", cat: "subagent", session: c,
        items: spans.map((sp) => ({ sp, a: sp.started_at || sp.ended_at || 0, b: sp.ended_at || (sp.status === "running" ? nowS : sp.started_at || 0) })),
        running: spans.filter((sp) => sp.status === "running").map((sp) => ({ sp, a: sp.started_at || nowS })),
        errors: spans.filter((sp) => sp.status === "error").length,
        total: 0, tools: new Map(), last: c.last_active || 0,
      });
      for (const sp of spans) for (const host of hostsOf(null, sp.summary)) {
        const t = touch(host); t.calls += 1; if (sp.status === "running") t.running += 1;
        t.items.push({ sp, a: sp.started_at || sp.ended_at || 0, b: sp.ended_at || (sp.status === "running" ? nowS : sp.started_at || 0), sub: c });
      }
    }
    const tlist = [...targets.values()].sort((x, y) => y.calls - x.calls);
    const shown = tlist.slice(0, 7);
    return { actors, targets: shown, hiddenTargets: tlist.length - shown.length, hyp, conf, children };
  }

  function arcPath(cx, cy, r, a0, a1) {
    const rad = (d) => (d * Math.PI) / 180;
    const x0 = cx + r * Math.cos(rad(a0)), y0 = cy + r * Math.sin(rad(a0));
    const x1 = cx + r * Math.cos(rad(a1)), y1 = cy + r * Math.sin(rad(a1));
    return "M" + x0.toFixed(1) + " " + y0.toFixed(1) + " A" + r + " " + r + " 0 0 1 " + x1.toFixed(1) + " " + y1.toFixed(1);
  }

  function renderSteps(m) {
    const ol = $("tr-steps");
    clear(ol);
    const o = currentOoda();
    const visits = {};
    for (const b of m.bands) visits[b.phase] = (visits[b.phase] || 0) + 1;
    PHASES.forEach((p, i) => {
      if (i) ol.append(h("li", { class: "ooda-steps__sep", "aria-hidden": "true" }, "—"));
      const cur = o && o.phase === p;
      ol.append(h("li", { class: "ooda-step" + (cur ? " is-current" : "") + (visits[p] ? " is-visited" : ""), "data-phase": p, "aria-current": cur ? "step" : null },
        cur ? h("i", { class: "ooda-step__dot" }) : null,
        p, cur && o.step != null ? h("b", null, " · " + o.step) : (visits[p] ? h("small", null, " ×" + visits[p]) : null)));
    });
  }

  function renderTicker() {
    const el = $("tr-ticker");
    let txt = "", cls = "";
    for (let i = S.events.length - 1; i >= 0 && !txt; i--) {
      const e = S.events[i];
      if (e.kind === "tool.result" && e.category === "finding") {
        const ok = !e.error && /"recorded"/.test(e.text || "");
        const call = S.events.find((x) => x.kind === "tool.call" && x.call_id === e.call_id);
        const title = (call && call.args && call.args.title) || "hallazgo";
        txt = (ok ? "★ HALLAZGO REGISTRADO · " : "✗ HALLAZGO RECHAZADO · ") + title; cls = ok ? "is-ok" : "is-err";
      } else if (e.kind === "tool.result" && e.error) {
        txt = "✗ " + (e.tool_display || e.tool) + " · " + oneLine(e.summary || e.text || "", 140); cls = "is-err";
      } else if (e.kind === "tool.call") {
        txt = "▶ " + (e.tool_display || e.tool) + " · " + oneLine(e.summary || "", 140); cls = "is-run";
      } else if (e.kind === "ooda") {
        txt = e.phase + " · " + e.step + " — " + (e.text || ""); cls = "is-ooda";
      }
    }
    el.textContent = txt;
    el.className = "graph__ticker " + cls;
    el.hidden = !txt;
  }

  function renderGraph(m) {
    renderSteps(m);
    renderTicker();
    const svg = $("tr-svg");
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    const g = graphModel(m);
    S.graphModel = g; S.graphTrace = m;
    const nA = Math.max(g.actors.length, 1), nT = Math.max(g.targets.length, 1);
    const ROW = 100, TROW = 80;
    const H = Math.max(520, nA * ROW + 60, nT * TROW + 60);
    const W = 1440, cy = H / 2;
    const TX = 250, HX = 600, AX = 880;
    const ay = (i) => cy + (i - (g.actors.length - 1) / 2) * ROW;
    const ty = (j) => cy + (j - (g.targets.length - 1) / 2) * TROW;
    S.graphBox = [0, 0, W, H];
    const vb = S.graphView || S.graphBox;
    svg.setAttribute("viewBox", vb.join(" "));

    const edges = sv("g", { class: "g-edges" });
    const nodes = sv("g", { class: "g-nodes" });
    svg.append(sv("defs", null,
      sv("radialGradient", { id: "g-glow" }, sv("stop", { offset: "0%", class: "g-glow-in" }), sv("stop", { offset: "100%", class: "g-glow-out" }))),
      sv("circle", { cx: HX, cy, r: 170, fill: "url(#g-glow)" }), edges, nodes);

    // ── objetivos (izquierda)
    if (!g.targets.length) {
      nodes.append(sv("text", { x: TX, y: cy + 4, class: "g-meta", "text-anchor": "end" }, "sin objetivos detectados todavía"));
    }
    g.targets.forEach((t, j) => {
      const y = ty(j);
      const live = t.running > 0;
      const path = "M" + (TX + 12) + " " + y + " C" + (TX + 170) + " " + y + " " + (HX - 190) + " " + cy + " " + (HX - 46) + " " + cy;
      const e = sv("path", { d: path, class: "g-edge g-edge--target" + (live ? " is-active" : ""), "data-gedge": "tgt:" + t.host, "stroke-width": (1.2 + Math.log2(1 + t.calls) * 0.7).toFixed(2) });
      if (live) e.style.animationDelay = animDelay(1);
      edges.append(e);
      const grp = sv("g", { class: "g-target g-sel" + (live ? " is-running" : ""), "data-gsel": "tgt:" + t.host, tabindex: 0, role: "button", "aria-label": "Objetivo " + t.host },
        live ? sv("circle", { cx: TX, cy: y, r: 9, class: "g-halo" }) : null,
        sv("circle", { cx: TX, cy: y, r: 9, class: "g-target__dot" }),
        sv("text", { x: TX - 20, y: y - 2, class: "g-host", "text-anchor": "end" }, oneLine(t.host, 30)),
        sv("text", { x: TX - 20, y: y + 15, class: "g-meta", "text-anchor": "end" },
          t.calls + (t.calls === 1 ? " llamada" : " llamadas"),
          t.ok ? sv("tspan", { class: "g-ok" }, " · " + t.ok + " ✓") : null,
          t.bad ? sv("tspan", { class: "g-bad" }, " · " + t.bad + " ✗") : null));
      if (live) grp.querySelector(".g-halo").style.animationDelay = animDelay(1.6);
      nodes.append(grp);
    });
    if (g.hiddenTargets > 0) {
      nodes.append(sv("text", { x: TX - 20, y: ty(g.targets.length - 1) + 40, class: "g-meta", "text-anchor": "end" }, "+" + g.hiddenTargets + " objetivos más"));
    }

    // ── Hermes (centro): anillo con las 4 fases OODA
    const o = currentOoda();
    const busy = g.actors.some((a) => a.running.length);
    const hg = sv("g", { class: "g-hermes g-sel" + (busy ? " is-running" : ""), "data-gsel": "hermes", tabindex: 0, role: "button", "aria-label": "Hermes, bucle OODA" });
    if (busy) { const halo = sv("circle", { cx: HX, cy, r: 30, class: "g-halo g-halo--big" }); halo.style.animationDelay = animDelay(2.2); hg.append(halo); }
    ["OBSERVE", "ORIENT", "DECIDE", "ACT"].forEach((p, i) => {
      const a0 = -90 + i * 90 + 5;
      const lit = o && (o.phase === p || o.phase === "REPORT");
      hg.append(sv("path", { d: arcPath(HX, cy, 40, a0, a0 + 80), class: "g-arc" + (lit ? " is-lit" : ""), "data-phase": p }));
    });
    hg.append(sv("circle", { cx: HX, cy, r: 30, class: "g-hermes__core" }),
      sv("text", { x: HX, y: cy + 5, class: "g-hermes__h", "text-anchor": "middle" }, "H"),
      sv("text", { x: HX, y: cy - 62, class: "g-kicker", "text-anchor": "middle" }, "HERMES · OODA"),
      sv("text", { x: HX, y: cy + 68, class: "g-phase", "text-anchor": "middle", "data-phase": o ? o.phase : "" }, o ? o.phase + " · " + o.step : "—"),
      sv("text", { x: HX, y: cy + 88, class: "g-meta", "text-anchor": "middle" },
        m.spans.length + " llamadas → " + g.hyp + " hallazgos → ", sv("tspan", { class: g.conf ? "g-ok" : "" }, g.conf + " confirmados")));
    nodes.append(hg);

    // ── actores (derecha): familias de tools y subagentes
    if (!g.actors.length) {
      nodes.append(sv("text", { x: AX, y: cy + 4, class: "g-meta" }, "sin tool-calls todavía"));
    }
    g.actors.forEach((ac, i) => {
      const y = ay(i);
      const live = ac.running.length > 0;
      const sub = ac.kind === "sub";
      const path = "M" + (HX + 46) + " " + cy + " C" + (HX + 170) + " " + cy + " " + (AX - 160) + " " + y + " " + (AX - 16) + " " + y;
      const e = sv("path", { d: path, class: "g-edge cat" + (sub ? " g-edge--sub" : "") + (live ? " is-active" : ""), "data-cat": ac.cat });
      if (live) e.style.animationDelay = animDelay(1);
      edges.append(e);

      const key = sub ? "sub:" + ac.session.id : "fam:" + ac.cat;
      e.setAttribute("data-gedge", key);
      const grp = sv("g", { class: "g-actor g-sel cat" + (live ? " is-running" : "") + (sub ? " g-actor--sub" : ""), "data-cat": ac.cat,
                             "data-gsel": key, tabindex: 0, role: "button", "aria-label": (sub ? "Subagente " : "Actor ") + (sub ? ac.session.title || ac.session.id : FAM_NAME[ac.cat] || ac.cat) });
      if (live) { const halo = sv("circle", { cx: AX, cy: y, r: 11, class: "g-halo" }); halo.style.animationDelay = animDelay(1.6); grp.append(halo); }
      if (sub) grp.append(sv("rect", { x: AX - 10, y: y - 10, width: 20, height: 20, rx: 3, class: "g-ring", transform: "rotate(45 " + AX + " " + y + ")" }));
      else grp.append(sv("circle", { cx: AX, cy: y, r: 11, class: "g-ring" }), sv("circle", { cx: AX, cy: y, r: 4, class: "g-core" }));

      const lx = AX + 24;
      const title = sub ? "Subagente · " + oneLine((ac.session.title || ac.session.id).replace(/^subagente\s*·\s*/i, ""), 46) : FAM_NAME[ac.cat] || ac.cat;
      const toolsTxt = sub ? "" : [...ac.tools.entries()].map(([n, c]) => n + (c > 1 ? " ×" + c : "")).join(" · ");
      grp.append(sv("text", { x: lx, y: y - 16, class: "g-title" }, title,
        toolsTxt ? sv("tspan", { class: "g-tools", dx: 10 }, oneLine(toolsTxt, 60)) : null));

      // fichas: últimas llamadas (ok = color de familia, error = rojo, en curso = verde vivo)
      const last = ac.items.slice(-16);
      const dots = sv("g", { class: "g-dots" });
      last.forEach((it, k) => {
        const d = sv("rect", { x: lx + k * 11, y: y - 6, width: 8, height: 8, rx: 2, class: "g-dot", "data-status": it.sp.status, "data-call": it.sp.call_id });
        d.append(sv("title", null, (it.sp.tool_display || it.sp.tool) + " · " + (it.sp.status === "running" ? "en curso" : fmtDur(it.b - it.a)) + " · " + oneLine(it.sp.summary || "", 80)));
        dots.append(d);
      });
      grp.append(dots);
      const n = ac.items.length;
      grp.append(sv("text", { x: lx + Math.max(last.length, 1) * 11 + 6, y: y + 2, class: "g-meta" },
        n + (n === 1 ? " llamada" : " llamadas"),
        ac.errors ? sv("tspan", { class: "g-bad" }, " · " + ac.errors + " ✗") : null,
        !sub && ac.total ? " · " + fmtDur(ac.total) : null,
        sub ? " · " + fmtAgo(ac.session.last_active) : null));

      // estado: lo que está corriendo ahora (o lo último que hizo)
      let st, stCls = "g-status";
      if (live) {
        const r = ac.running[ac.running.length - 1];
        st = "▶ " + (r.sp.tool_display || r.sp.tool) + " · " + oneLine(r.sp.summary || "", 52);
        stCls += " is-run";
        const t = sv("text", { x: lx, y: y + 22, class: stCls }, st, sv("tspan", { class: "g-elapsed", dx: 10, "data-since": r.a }, fmtDur(m.nowS - r.a)));
        grp.append(t);
      } else {
        const it = ac.items[ac.items.length - 1];
        st = it ? "último: " + oneLine(it.sp.summary || it.sp.tool || "", 58) + (it.sp.status === "error" ? "  ✗" : "  ✓ " + fmtDur(it.b - it.a)) : "sin actividad";
        grp.append(sv("text", { x: lx, y: y + 22, class: stCls }, st));
      }
      nodes.append(grp);
    });
    applyGraphSel();
  }

  // ── selección: panel lateral con el detalle del nodo
  function applyGraphSel() {
    const svg = $("tr-svg");
    const key = S.graphSel;
    svg.classList.toggle("has-sel", !!key);
    svg.querySelectorAll("[data-gsel]").forEach((n) => n.classList.toggle("is-sel", n.dataset.gsel === key));
    svg.querySelectorAll("[data-gedge]").forEach((n) => n.classList.toggle("is-sel", n.dataset.gedge === key));
    renderDrawer();
  }
  function selectGraph(key, callId) {
    S.graphSel = key && key === S.graphSel && !callId ? null : key;
    if (callId) { S.graphOpen.add(callId); S.graphFocusCall = callId; }
    applyGraphSel();
  }

  async function loadCallDetail(sp, box) {
    const argsPre = h("pre", { class: "block" }, "…"), outPre = h("pre", { class: "block" }, sp.status === "running" ? "(en curso)" : "…");
    box.append(h("div", { class: "gd-k" }, "Argumentos"), argsPre, h("div", { class: "gd-k" }, "Resultado"), outPre);
    const get = async (seq) => {
      if (!seq) return null;
      if (!S.evCache.has(seq)) S.evCache.set(seq, await api("/api/events/" + seq));
      return S.evCache.get(seq);
    };
    try {
      const c = await get(sp.call_seq);
      argsPre.textContent = c ? JSON.stringify(c.args != null ? c.args : {}, null, 2) : "(no disponible)";
      const r = await get(sp.result_seq);
      if (r) outPre.textContent = r.output != null ? r.output : outputText(r.text);
      else if (sp.status !== "running") outPre.textContent = sp.result_preview || "—";
    } catch (e) { argsPre.textContent = "error: " + e; }
  }

  function callList(items, nowS, showSub, onToggle) {
    onToggle = onToggle || renderDrawer;
    const ol = h("ol", { class: "gd-calls" });
    const sorted = items.slice().sort((x, y) => (y.a || 0) - (x.a || 0));
    if (!sorted.length) ol.append(h("li", { class: "muted" }, "Sin llamadas."));
    for (const it of sorted.slice(0, 80)) {
      const sp = it.sp, run = sp.status === "running", err = sp.status === "error";
      const open = S.graphOpen.has(sp.call_id);
      const li = h("li", { class: "gd-call" + (open ? " is-open" : "") + (S.graphFocusCall === sp.call_id ? " is-focus" : "") });
      const head = h("button", { type: "button", class: "gd-call__head", "aria-expanded": open ? "true" : "false" },
        h("span", { class: "tm" }, fmtTime(it.a)),
        h("span", { class: "gd-call__body" },
          h("span", { class: "t cat", "data-cat": sp.category }, sp.tool_display || sp.tool || "?"),
          showSub && it.sub ? h("span", { class: "gd-sub" }, " ↳ subagente") : null,
          h("span", { class: "c" }, " " + oneLine(sp.summary || "", 160))),
        run ? h("span", { class: "st s--run", "data-since": it.a }, fmtDur(nowS - it.a))
            : h("span", { class: "st " + (err ? "s--err" : "s--ok") }, (err ? "✗ " : "✓ ") + fmtDur(sp.duration != null ? sp.duration : it.b - it.a)));
      head.addEventListener("click", () => {
        if (S.graphOpen.has(sp.call_id)) S.graphOpen.delete(sp.call_id); else S.graphOpen.add(sp.call_id);
        S.graphFocusCall = null;
        onToggle();
      });
      li.append(head);
      if (open) { const box = h("div", { class: "gd-call__detail" }); li.append(box); loadCallDetail(sp, box); }
      ol.append(li);
    }
    return ol;
  }

  function gdStats(pairs) {
    return h("dl", { class: "gd-stats" }, ...pairs.filter(Boolean).map(([k, v, cls]) => h("div", null, h("dt", null, k), h("dd", { class: cls || null }, v))));
  }

  // Detalle de una tool de la tabla "Por herramienta": todas sus llamadas de esta sesión, cada
  // una desplegable a sus argumentos y resultado reales (reutiliza callList/gdStats del grafo).
  function renderToolDetail(m) {
    const box = $("tr-tool-detail");
    const name = S.toolSelected;
    if (!name || !m) { box.hidden = true; return; }
    const sum = (S.trace && S.trace.summary) || {};
    const agg = (sum.tools || []).find((t) => t.tool === name);
    if (!agg) { S.toolSelected = null; box.hidden = true; return; }
    const items = m.spans.filter((sp) => (sp.tool_display || sp.tool || "?") === name)
      .map((sp) => ({ sp, a: sp.started_at || sp.ended_at || 0, b: sp.ended_at || (sp.status === "running" ? m.nowS : sp.started_at || 0) }));
    const keep = box.scrollTop;
    clear(box);
    const close = h("button", { type: "button", class: "btn btn--ghost btn--sm gd-close", "aria-label": "Cerrar" }, "✕");
    close.addEventListener("click", () => { S.toolSelected = null; renderToolDetail(m); renderTrace(); });
    box.append(close,
      h("header", { class: "gd-head cat", "data-cat": agg.category },
        h("span", { class: "gd-kicker" }, "Tool"), h("h4", { class: "gd-title" }, name)),
      gdStats([["Llamadas", fmtInt(agg.calls)], ["En curso", fmtInt(agg.running || 0), agg.running ? "s--run" : ""],
               ["Errores", fmtInt(agg.errors), agg.errors ? "s--err" : ""], ["Media", fmtDur(agg.avg)],
               ["Máx", fmtDur(agg.max)], ["Tiempo total", fmtDur(agg.total)]]),
      h("div", { class: "gd-k" }, "Llamadas de esta sesión (clic para ver argumentos y resultado)"),
      callList(items, m.nowS, false, () => renderToolDetail(m)));
    box.hidden = false;
    box.scrollTop = keep;
  }

  function renderDrawer() {
    const dr = $("tr-drawer");
    const key = S.graphSel, g = S.graphModel, m = S.graphTrace;
    const wrap = $("tr-graph");
    if (!key || !g || !m) { dr.hidden = true; wrap.classList.remove("has-drawer"); return; }
    wrap.classList.add("has-drawer");
    const keep = dr.scrollTop;
    clear(dr);
    const close = h("button", { type: "button", class: "btn btn--ghost btn--sm gd-close", "aria-label": "Cerrar" }, "✕");
    close.addEventListener("click", () => selectGraph(null));
    let body = null;
    if (key === "hermes") {
      const o = currentOoda();
      let thought = null;
      for (let i = S.events.length - 1; i >= 0; i--) if (S.events[i].kind === "reasoning") { thought = S.events[i]; break; }
      const steps = h("ol", { class: "gd-steps" });
      for (const b of m.bands.slice().reverse().slice(0, 40)) {
        steps.append(h("li", null, h("span", { class: "wf-ph", "data-phase": b.phase }, (PH_SHORT[b.phase] || b.phase) + " " + b.step),
          h("span", { class: "c" }, b.text || ""), h("span", { class: "st" }, fmtDur(b.end - b.ts))));
      }
      body = [h("header", { class: "gd-head" }, h("span", { class: "gd-kicker" }, "Hermes · bucle OODA"),
                h("h4", null, o ? o.phase + " · step " + o.step : "—"), o && o.text ? h("p", { class: "gd-lead" }, o.text) : null),
        gdStats([["Tool-calls", fmtInt(m.spans.length)], ["Hallazgos", fmtInt(g.hyp)], ["Confirmados", fmtInt(g.conf), g.conf ? "s--ok" : ""],
                 ["Subagentes", fmtInt(g.children.length)]]),
        thought ? h("div", { class: "gd-k" }, "Último razonamiento") : null,
        thought ? h("p", { class: "gd-thought" }, oneLine(thought.text || "", 600)) : null,
        h("div", { class: "gd-k" }, "Pasos OODA (más reciente arriba)"), steps];
    } else if (key.startsWith("fam:")) {
      const cat = key.slice(4), ac = g.actors.find((x) => x.kind === "fam" && x.cat === cat);
      if (!ac) { S.graphSel = null; dr.hidden = true; wrap.classList.remove("has-drawer"); return; }
      body = [h("header", { class: "gd-head cat", "data-cat": cat }, h("span", { class: "gd-kicker" }, "Actor · familia de tools"),
                h("h4", { class: "gd-title" }, FAM_NAME[cat] || cat),
                h("p", { class: "gd-lead" }, [...ac.tools.entries()].map(([n, c]) => n + " ×" + c).join(" · "))),
        gdStats([["Llamadas", fmtInt(ac.items.length)], ["En curso", fmtInt(ac.running.length), ac.running.length ? "s--run" : ""],
                 ["Errores", fmtInt(ac.errors), ac.errors ? "s--err" : ""], ["Tiempo", fmtDur(ac.total)]]),
        h("div", { class: "gd-k" }, "Llamadas (clic para ver argumentos y resultado)"), callList(ac.items, m.nowS)];
    } else if (key.startsWith("sub:")) {
      const sid = key.slice(4), ac = g.actors.find((x) => x.kind === "sub" && x.session.id === sid);
      if (!ac) { S.graphSel = null; dr.hidden = true; wrap.classList.remove("has-drawer"); return; }
      const c = ac.session;
      const go = h("button", { type: "button", class: "btn" }, "Abrir la sesión del subagente →");
      go.addEventListener("click", () => { $("follow-active").checked = false; S.graphSel = null; selectSession(sid); });
      body = [h("header", { class: "gd-head cat", "data-cat": "subagent" }, h("span", { class: "gd-kicker" }, "Subagente delegado"),
                h("h4", { class: "gd-title" }, c.title || c.id), h("p", { class: "gd-lead" }, (ac.running.length ? "activo" : "sin tools en curso") + " · " + fmtAgo(c.last_active))),
        gdStats([["Llamadas", fmtInt(ac.items.length)], ["En curso", fmtInt(ac.running.length), ac.running.length ? "s--run" : ""],
                 ["Errores", fmtInt(ac.errors), ac.errors ? "s--err" : ""],
                 ["Coste", c.cost_usd != null ? "$" + Number(c.cost_usd).toFixed(4) : "—"]]),
        h("div", { class: "gd-actions" }, go),
        h("div", { class: "gd-k" }, "Llamadas del subagente"), callList(ac.items, m.nowS)];
    } else if (key.startsWith("tgt:")) {
      const host = key.slice(4), t = g.targets.find((x) => x.host === host);
      if (!t) { S.graphSel = null; dr.hidden = true; wrap.classList.remove("has-drawer"); return; }
      const fl = h("ul", { class: "gd-findings" });
      for (const f of t.findings) {
        fl.append(h("li", null, h("span", { class: "chip chip--" + (f.done && !f.recorded ? "rejected" : (f.state || "hypothesis")) }, f.done && !f.recorded ? "rechazado" : (f.state || "?")),
          " ", f.title, f.why ? h("div", { class: "s--err" }, f.why) : null));
      }
      body = [h("header", { class: "gd-head" }, h("span", { class: "gd-kicker" }, "Objetivo"), h("h4", { class: "gd-title gd-title--host" }, host)),
        gdStats([["Llamadas", fmtInt(t.calls)], ["En curso", fmtInt(t.running), t.running ? "s--run" : ""],
                 ["Hallazgos ✓", fmtInt(t.ok), t.ok ? "s--ok" : ""], ["Rechazados", fmtInt(t.bad), t.bad ? "s--err" : ""]]),
        t.findings.length ? h("div", { class: "gd-k" }, "Hallazgos sobre este objetivo") : null, t.findings.length ? fl : null,
        h("div", { class: "gd-k" }, "Llamadas que lo tocan"), callList(t.items, m.nowS, true)];
    }
    dr.append(close, ...(body || []).filter(Boolean));
    dr.hidden = false;
    dr.scrollTop = keep;
    if (S.graphFocusCall) {
      const f = dr.querySelector(".gd-call.is-focus");
      if (f) f.scrollIntoView({ block: "nearest" });
      S.graphFocusCall = null;
    }
  }

  // ── zoom / pan del grafo (viewBox)
  (function setupGraphNav() {
    const svg = $("tr-svg");
    const view = () => (S.graphView || S.graphBox || [0, 0, 1440, 520]).slice();
    const apply = (v) => { S.graphView = v; svg.setAttribute("viewBox", v.join(" ")); };
    const zoomAt = (f, px, py) => {
      const v = view();
      const nw = clamp(v[2] * f, 260, 4000), nh = v[3] * (nw / v[2]);
      apply([px - (px - v[0]) * (nw / v[2]), py - (py - v[1]) * (nh / v[3]), nw, nh]);
    };
    const toSvg = (e) => {
      const r = svg.getBoundingClientRect(), v = view();
      return [v[0] + ((e.clientX - r.left) / r.width) * v[2], v[1] + ((e.clientY - r.top) / r.height) * v[3]];
    };
    svg.addEventListener("wheel", (e) => {
      if (!e.ctrlKey && !e.metaKey) return;  // la rueda sola sigue haciendo scroll de la página
      e.preventDefault();
      const [px, py] = toSvg(e);
      zoomAt(e.deltaY > 0 ? 1.15 : 1 / 1.15, px, py);
    }, { passive: false });
    svg.addEventListener("keydown", (e) => {
      const n = e.target.closest && e.target.closest("[data-gsel]");
      if (n && (e.key === "Enter" || e.key === " ")) { e.preventDefault(); selectGraph(n.dataset.gsel); }
    });
    svg.addEventListener("pointerdown", (e) => {
      if (e.button !== 0) return;
      const r = svg.getBoundingClientRect(), v0 = view(), x0 = e.clientX, y0 = e.clientY;
      const downNode = e.target.closest("[data-gsel]"), downCall = e.target.closest("[data-call]");
      let moved = false;
      svg.classList.add("is-panning");
      try { svg.setPointerCapture(e.pointerId); } catch (_) { /* opcional */ }
      const move = (ev) => {
        if (!moved && Math.hypot(ev.clientX - x0, ev.clientY - y0) < 4) return;
        moved = true;
        apply([v0[0] - ((ev.clientX - x0) / r.width) * v0[2], v0[1] - ((ev.clientY - y0) / r.height) * v0[3], v0[2], v0[3]]);
      };
      const up = () => {
        if (!moved) {
          if (downNode) selectGraph(downNode.dataset.gsel, downCall ? downCall.dataset.call : null);
          else if (S.graphSel) selectGraph(null);
        }
        svg.classList.remove("is-panning"); svg.removeEventListener("pointermove", move); svg.removeEventListener("pointerup", up); svg.removeEventListener("pointercancel", up); };
      svg.addEventListener("pointermove", move); svg.addEventListener("pointerup", up); svg.addEventListener("pointercancel", up);
    });
    document.addEventListener("keydown", (e) => { if (e.key === "Escape" && S.graphSel && S.view === "traces") selectGraph(null); });
    svg.addEventListener("dblclick", () => { S.graphView = null; if (S.graphBox) svg.setAttribute("viewBox", S.graphBox.join(" ")); });
    document.querySelectorAll("[data-gzoom]").forEach((b) => b.addEventListener("click", () => {
      const v = view();
      if (b.dataset.gzoom === "fit") { S.graphView = null; if (S.graphBox) svg.setAttribute("viewBox", S.graphBox.join(" ")); return; }
      zoomAt(b.dataset.gzoom === "in" ? 1 / 1.25 : 1.25, v[0] + v[2] / 2, v[1] + v[3] / 2);
    }));
  })();

  // ── Grafo / Cascada
  function setTraceMode(mode) {
    S.traceMode = mode === "cascade" ? "cascade" : "graph";
    try { localStorage.setItem("vweb.traceMode", S.traceMode); } catch (_) { /* opcional */ }
    $("tr-graph-card").hidden = S.traceMode !== "graph";
    $("tr-cascade-card").hidden = S.traceMode !== "cascade";
    document.querySelectorAll("[data-trmode]").forEach((b) => b.setAttribute("aria-pressed", b.dataset.trmode === S.traceMode ? "true" : "false"));
  }
  document.querySelectorAll("[data-trmode]").forEach((b) => b.addEventListener("click", () => setTraceMode(b.dataset.trmode)));
  try { setTraceMode(localStorage.getItem("vweb.traceMode") || "graph"); } catch (_) { setTraceMode("graph"); }


  async function renderTraceDetail(sp, quiet) {
    const box = $("tr-detail");
    if (!quiet) {
      clear(box);
      box.hidden = false;
      box.append(h("header", { class: "card__head" }, h("h3", null, "Detalle de la llamada"),
        h("button", { class: "btn btn--ghost", type: "button", onclick: () => { box.hidden = true; S.traceSelected = null; } }, "Cerrar")));
    } else {
      while (box.childNodes.length > 1) box.removeChild(box.lastChild);
    }
    const dur = sp.duration != null ? sp.duration : (sp.status === "running" && sp.started_at ? now() - sp.started_at : null);
    box.append(h("dl", { class: "detail-grid" },
      h("div", null, h("dt", null, "Tool"), h("dd", null, sp.tool || "?")),
      h("div", null, h("dt", null, "Estado"), h("dd", { class: sp.status === "error" ? "s--err" : sp.status === "running" ? "s--run" : "s--ok" }, sp.status)),
      h("div", null, h("dt", null, "Duración"), h("dd", null, fmtDur(dur))),
      h("div", null, h("dt", null, "Fase OODA"), h("dd", null, sp.phase ? sp.phase + " · step " + sp.step : "—")),
      h("div", null, h("dt", null, "Inicio"), h("dd", null, fmtDateTime(sp.started_at))),
      h("div", null, h("dt", null, "Fin"), h("dd", null, fmtDateTime(sp.ended_at))),
      h("div", null, h("dt", null, "Familia"), h("dd", null, CAT_LABEL[sp.category] || sp.category || "—")),
      h("div", null, h("dt", null, "call_id"), h("dd", null, sp.call_id))));
    const argsPre = h("pre", { class: "block" }, "…");
    const outPre = h("pre", { class: "block" }, sp.result_preview || (sp.status === "running" ? "(en curso)" : "—"));
    box.append(h("h3", { class: "muted", style: { fontSize: "11px", letterSpacing: ".2em", textTransform: "uppercase", marginTop: "6px" } }, "Argumentos"), argsPre,
      h("h3", { class: "muted", style: { fontSize: "11px", letterSpacing: ".2em", textTransform: "uppercase", marginTop: "12px" } }, "Resultado"), outPre);
    try {
      if (sp.call_seq) {
        const ev = await api("/api/events/" + sp.call_seq);
        argsPre.textContent = JSON.stringify(ev.args != null ? ev.args : {}, null, 2);
      } else argsPre.textContent = "(no disponible)";
      if (sp.result_seq) {
        const ev = await api("/api/events/" + sp.result_seq);
        outPre.textContent = ev.output != null ? ev.output : outputText(ev.text);
      }
    } catch (e) { argsPre.textContent = "error: " + e; }
  }

  // ───────────────────────────────────────────────────────── PoC
  const pocRefresh = throttle(() => loadPocs(), 1200);

  async function loadPocs() {
    try {
      const doc = await api("/api/pocs");
      const list = doc.data || [];
      const prev = S.knownPocs;
      const next = new Map(list.map((p) => [p.id, p.store_status]));
      if (prev) {
        for (const p of list) {
          if (prev.get(p.id) === p.store_status) continue;
          if (p.confirmed && p.store_status === "recorded") toast("ok", "PoC confirmado", p.title, () => openPoc(p));
          else if (p.store_status === "rejected" && p.state === "confirmed") toast("err", "Hallazgo rechazado", p.title + " — sin evidencia reproducible", () => openPoc(p));
        }
      }
      S.knownPocs = next;
      S.pocs = list;
      const confirmed = list.filter((p) => p.confirmed && p.store_status === "recorded").length;
      const badge = $("poc-count");
      badge.hidden = confirmed === 0;
      badge.textContent = confirmed;
      if (S.view === "pocs") renderPocList();
      if (S.pocSelected && S.view === "pocs") {
        const cur = list.find((p) => p.id === S.pocSelected.id);
        if (cur && cur.store_status !== S.pocSelected.store_status) openPoc(cur);
      }
    } catch (_) { /* reintenta en el siguiente ciclo */ }
  }

  // Severidad derivada del título del hallazgo (el modelo no la trae estructurada):
  // 1º por CVSS numérico, 2º por palabra explícita (ES/EN); si no hay nada -> "info".
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const SEV_LABEL = { critical: "CRÍTICA", high: "ALTA", medium: "MEDIA", low: "BAJA", info: "INFO" };
  const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
  function aiSevLookup(title) {
    const m = S.aiSev;
    if (!m || typeof m !== "object") return null;
    if (m[title]) return m[title];
    const nk = (title || "").replace(/\s+/g, " ").trim().toLowerCase();
    for (const k in m) {
      const kk = k.replace(/\s+/g, " ").trim().toLowerCase();
      if (kk === nk || kk.slice(0, 60) === nk.slice(0, 60) || kk.indexOf(nk) >= 0 || nk.indexOf(kk) >= 0) return m[k];
    }
    return null;
  }

  async function loadSeverities() {
    try {
      const d = await api("/api/severities");
      S.aiSev = d && typeof d === "object" ? d : {};
      if (S.view === "pocs") renderPocList();
    } catch (_) { /* reintenta */ }
  }

  function pocSeverity(p) {
    const hit = aiSevLookup(p.title || "");
    if (hit) {
      const s = (typeof hit === "string" ? hit : (hit.severity || hit.sev || "")).toLowerCase();
      if (SEV_RANK[s] !== undefined) {
        p._sevBy = "ia";
        p._rationale = (typeof hit === "object" && hit.rationale) ? hit.rationale : "";
        return s;
      }
    }
    p._sevBy = "regex"; p._rationale = "";
    const t = (p.title || "").toUpperCase();
    const m = t.match(/CVSS\s*(\d{1,2}(?:\.\d)?)/);
    const score = m ? parseFloat(m[1]) : null;
    if (/\bCRIT[IÍ]CA\b|\bCRITICAL\b/.test(t) || (score != null && score >= 9.0)) return "critical";
    if (/\bHIGH\b|\bALTA\b/.test(t) || (score != null && score >= 7.0)) return "high";
    if (/\bMEDIUM\b|\bMEDIA\b/.test(t) || (score != null && score >= 4.0)) return "medium";
    if (/\bLOW\b|\bBAJA\b/.test(t) || (score != null && score > 0)) return "low";
    return "info";
  }

  function renderPocList() {
    const ul = $("poc-list");
    clear(ul);
    let base = S.pocs;
    if ($("poc-only-session").checked) base = base.filter((p) => p.session_id === S.sid);
    if ($("poc-only-confirmed").checked) base = base.filter((p) => p.confirmed);

    // severidad por item + conteo por nivel (sobre la base ya filtrada)
    const counts = { all: base.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const p of base) { p._sev = pocSeverity(p); counts[p._sev]++; }
    for (const sev of ["all", ...SEV_ORDER]) {
      const el = document.querySelector('.sevfilter__n[data-n="' + sev + '"]');
      if (el) el.textContent = counts[sev];
      const btn = document.querySelector('.sevfilter[data-sev="' + sev + '"]');
      if (btn) btn.classList.toggle("is-on", S.pocSev === sev);
    }

    let list = S.pocSev === "all" ? base.slice() : base.filter((p) => p._sev === S.pocSev);
    // peores primero, y dentro de cada nivel lo más reciente arriba
    list.sort((a, b) => (SEV_RANK[b._sev] - SEV_RANK[a._sev]) || ((b.ts || 0) - (a.ts || 0)));
    $("poc-empty").hidden = list.length > 0;

    for (const p of list) {
      const rejected = p.store_status === "rejected";
      const cls = "poc" + (p.confirmed && !rejected ? " poc--confirmed" : "") + (rejected ? " poc--rejected" : "");
      ul.append(h("li", null, h("button", {
        class: cls, type: "button", "aria-current": S.pocSelected && S.pocSelected.id === p.id ? "true" : "false",
        onclick: () => openPoc(p),
      }, h("span", { class: "poc__title" },
          h("span", {
            class: "sevbadge sevbadge--" + p._sev + (p._sevBy === "ia" ? " sevbadge--ia" : ""),
            title: p._sevBy === "ia" ? ("Severidad asignada por IA" + (p._rationale ? ": " + p._rationale : "")) : "Severidad (derivada del título)",
          }, SEV_LABEL[p._sev] + (p._sevBy === "ia" ? " ·IA" : "")),
          p.title),
        h("span", { class: "poc__meta" },
          h("span", { class: "chip chip--" + (rejected ? "rejected" : (p.state || "hypothesis")) }, rejected ? "rechazado" : (p.state || "?")),
          p.target ? h("span", null, oneLine(p.target, 40)) : null,
          h("span", null, fmtAgo(p.ts))))));
    }
  }
  ["poc-only-session", "poc-only-confirmed"].forEach((id) => $(id).addEventListener("change", renderPocList));
  document.querySelectorAll(".sevfilter").forEach((btn) => btn.addEventListener("click", () => {
    S.pocSev = btn.getAttribute("data-sev") || "all";
    renderPocList();
  }));

  const genReportBtn = $("poc-genreport");
  if (genReportBtn) genReportBtn.addEventListener("click", async () => {
    const sid = S.sid || (S.sessions.find((s) => s.source === "api_server") || {}).id;
    if (!sid) { toast("err", "Sin sesión", "Selecciona una sesión con hallazgos antes de generar el informe."); return; }
    genReportBtn.disabled = true;
    const prev = genReportBtn.textContent;
    genReportBtn.textContent = "Generando…";
    try {
      const r = await fetch("/api/report", {
        method: "POST", credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ session_id: sid }),
      });
      if (!r.ok) throw new Error("HTTP " + r.status);
      const d = await r.json();
      toast("ok", "Informe en marcha", "El agente redacta el informe en una sesión nueva — ábrela para seguirlo.", () => {
        if (d.run_id) selectSession(d.run_id);
      });
      refreshSessionsSoon();
      pollReportReady();
    } catch (e) {
      toast("err", "No se pudo iniciar el informe", String(e));
    } finally {
      genReportBtn.disabled = false;
      genReportBtn.textContent = prev;
    }
  });

  function pollReportReady() {
    let tries = 0;
    const iv = setInterval(async () => {
      tries++;
      try {
        const rr = await fetch("/api/report.html", { cache: "no-store" });
        if (rr.ok) {
          clearInterval(iv);
          loadSeverities();
          toast("ok", "Informe listo", "Pulsa aquí para abrir pentest-report.html.", () => window.open("/api/report.html", "_blank"));
        }
      } catch (_) { /* reintenta en el siguiente ciclo */ }
      if (tries >= 90) clearInterval(iv);  // ~6 min máx
    }, 4000);
  }

  const repView = $("rep-view");
  if (repView) repView.addEventListener("click", () => {
    if (S.view !== "pocs") showView("pocs");
    const box = $("poc-detail");
    clear(box);
    box.append(
      h("div", { class: "report-frame__bar" },
        h("span", { class: "muted", style: { fontSize: "11px" } }, "Informe completo — reproducción y verbatim"),
        h("a", { class: "repbtn", href: "/api/report.html", target: "_blank" }, "Abrir en pestaña"),
        h("a", { class: "repbtn", href: "/api/report.pdf?dl=1" }, "PDF"),
        h("a", { class: "repbtn", href: "/api/report.md?dl=1" }, "MD"),
        h("a", { class: "repbtn", href: "/api/report.txt?dl=1" }, "TXT")),
      h("iframe", { class: "report-frame", src: "/api/report.html?ts=" + Date.now() }));
  });

  async function openPoc(p) {
    S.pocSelected = p;
    if (S.view !== "pocs") showView("pocs");
    renderPocList();
    const box = $("poc-detail");
    clear(box);
    box.append(h("p", { class: "empty" }, "Cargando…"));
    try {
      const doc = await api("/api/sessions/" + encodeURIComponent(p.session_id) + "/pocs");
      const poc = (doc.data || []).find((x) => x.call_id === p.call_id);
      if (!poc) throw new Error("no encontrado");
      renderPocDetail(poc);
    } catch (e) {
      clear(box);
      box.append(h("p", { class: "empty" }, "No se pudo cargar el PoC: " + e));
    }
  }

  function sectionTitle(text) {
    return h("h3", { class: "muted", style: { fontSize: "11px", letterSpacing: ".24em", textTransform: "uppercase" } }, text);
  }

  function renderPocDetail(poc) {
    stopPlayer();
    const box = $("poc-detail");
    clear(box);
    const f = poc.finding;
    const rep = poc.reproduction || {};
    const exe = rep.execution;
    const rejected = poc.store_status === "rejected";

    const meta = [];
    const add = (k, v) => { if (v) meta.push(h("span", null, k + " ", h("b", null, v))); };
    add("target", f.target); add("técnica", f.technique_id); add("confianza", f.confidence);
    add("engagement", f.engagement_id); add("fase", poc.phase ? poc.phase + " · " + poc.step : null);
    add("cuándo", fmtDateTime(poc.ts));
    box.append(h("div", { class: "poc-head" },
      h("div", null, h("span", { class: "chip chip--" + (rejected ? "rejected" : (f.state || "hypothesis")) }, rejected ? "rechazado" : f.state)),
      h("h2", null, f.title), h("div", { class: "meta" }, meta)));

    if (rejected) box.append(h("div", { class: "verdict verdict--err" }, "El store de hallazgos lo rechazó: " + (poc.store_error || "evidencia insuficiente") + ". El agente debe aportar comando + salida verbatim o bajarlo a partial/hypothesis."));
    else if (poc.store_status === "recorded" && poc.confirmed) box.append(h("div", { class: "verdict verdict--ok" }, exe
      ? "PoC confirmado y registrado. El comando de la evidencia coincide con una ejecución real de la sesión (" + exe.tool + ", exit " + exe.returncode + ", " + fmtDur(exe.duration) + ")."
      : "PoC confirmado y registrado. El comando de la evidencia no se encontró entre las ejecuciones de esta sesión: se reproduce la salida que pegó el agente."));
    else if (poc.store_status === "recorded") box.append(h("div", { class: "verdict verdict--pending" }, "Hallazgo registrado como " + f.state + "."));
    else box.append(h("div", { class: "verdict verdict--pending" }, "Registrando hallazgo…"));

    // Reproductor
    const screen = h("div", { class: "player__screen", "aria-live": "off" });
    const prog = h("i");
    const playBtn = h("button", { class: "btn", type: "button" }, "▶ Reproducir");
    const restartBtn = h("button", { class: "btn btn--ghost", type: "button" }, "↺");
    const speed = h("select", { class: "btn btn--ghost", "aria-label": "Velocidad" },
      ["1", "2", "4", "10"].map((v) => h("option", { value: v }, v + "×")));
    const base = "/api/sessions/" + encodeURIComponent(poc.session_id) + "/pocs/" + encodeURIComponent(poc.call_id);
    box.append(h("section", { class: "player" },
      h("div", { class: "player__bar" },
        h("span", { class: "player__dots" }, h("i"), h("i"), h("i")),
        h("span", { class: "player__title" }, "replay · " + f.title),
        playBtn, restartBtn, speed,
        h("a", { class: "btn btn--ghost", href: base + ".cast", download: "" }, ".cast"),
        h("a", { class: "btn btn--ghost", href: base + ".md", download: "" }, ".md")),
      h("div", { class: "player__progress" }, prog),
      screen));
    S.player = makePlayer(poc.replay || [], screen, prog, playBtn, speed);
    playBtn.addEventListener("click", () => S.player.toggle());
    restartBtn.addEventListener("click", () => S.player.restart());
    S.player.play();

    // Ruta OODA
    box.append(sectionTitle("Cómo llegó hasta aquí · ruta OODA"));
    const path = h("ol", { class: "path" });
    if (!poc.ooda_path.length) path.append(h("li", null, h("span", { class: "ph" }, "—"), h("span", { class: "muted" }, "El agente no emitió líneas de estado OODA.")));
    for (const s of poc.ooda_path) {
      path.append(h("li", { "data-phase": s.phase },
        h("span", { class: "ph" }, s.phase + " · " + s.step), h("span", null, s.text)));
    }
    box.append(path);

    // Pasos
    box.append(sectionTitle("Pasos ejecutados antes del hallazgo" + (poc.chain_omitted ? " · " + poc.chain_omitted + " anteriores omitidos" : "")));
    const steps = h("ol", { class: "steps" });
    const toolSteps = poc.chain.filter((s) => s.kind === "tool.call");
    if (!toolSteps.length) steps.append(h("li", null, h("span", { class: "muted" }, "—")));
    for (const s of toolSteps) {
      const isExe = exe && s.call_id === exe.call_id;
      const r = s.result;
      steps.append(h("li", { class: isExe ? "is-exec" : null },
        h("span", { class: "t cat", "data-cat": s.category }, s.tool + (isExe ? " ◀" : "")),
        h("span", { class: "c" }, oneLine(s.summary, 260) + (r ? "  →  " + oneLine(r.summary, 140) : "")),
        h("span", { class: r ? (r.status === "error" ? "s--err" : "s--ok") : "s--run" }, r ? (r.status === "error" ? "✗ " : "✓ ") + fmtDur(r.duration) : "…")));
    }
    box.append(steps);

    // Evidencia
    box.append(sectionTitle("Evidencia"));
    const command = (exe && exe.command) || rep.command;
    if (command) {
      box.append(h("pre", { class: "block" }, "$ " + command));
      const out = exe && exe.output != null ? exe.output : rep.evidence_output;
      if (out) box.append(h("pre", { class: "block" }, out), h("p", { class: "note" }, exe ? "Salida real de la ejecución enlazada" + (exe.output_truncated ? " (recortada; el crudo íntegro está en la sesión)" : "") + "." : "Salida pegada por el agente en la evidencia."));
    } else if (rep.artifact_ref) {
      box.append(h("p", { class: "note" }, "Evidencia en el artefacto " + rep.artifact_ref.execution_id + "/" + rep.artifact_ref.name + " del plano de datos de Kali (:8901)."));
    } else {
      box.append(h("p", { class: "note" }, "La evidencia no incluye un comando reproducible."));
    }
  }

  function makePlayer(frames, screen, prog, playBtn, speedSel) {
    let i = 0, timer = null, playing = false, typing = null;
    const total = frames.length ? frames[frames.length - 1].t : 0;
    const cls = (s) => "fr fr--" + s;
    function setBtn() { playBtn.textContent = playing ? "❚❚ Pausa" : (i >= frames.length ? "▶ Otra vez" : "▶ Reproducir"); }
    function progress() { prog.style.width = (frames.length ? (i / frames.length) * 100 : 0) + "%"; }
    function render(fr, done) {
      const el = h("div", { class: cls(fr.stream) });
      screen.append(el);
      if (fr.stream === "cmd" && !reducedMotion && playing) {
        const text = fr.text; let k = 0;
        const per = Math.max(4, Math.min(28, 1400 / Math.max(1, text.length))) / Number(speedSel.value);
        const caret = h("span", { class: "caret" });
        el.append(document.createTextNode(""), caret);
        typing = setInterval(() => {
          k += 1; el.firstChild.textContent = text.slice(0, k);
          screen.scrollTop = screen.scrollHeight;
          if (k >= text.length) { clearInterval(typing); typing = null; caret.remove(); done(); }
        }, per);
      } else {
        el.textContent = fr.text;
        done();
      }
      screen.scrollTop = screen.scrollHeight;
    }
    function step() {
      if (!playing) return;
      if (i >= frames.length) { playing = false; setBtn(); screen.append(h("span", { class: "caret" })); return; }
      const fr = frames[i];
      render(fr, () => {
        i += 1; progress();
        const next = frames[i];
        const gap = next ? Math.max(0, next.t - fr.t) : 0;
        timer = setTimeout(step, (gap * 1000) / Number(speedSel.value));
      });
    }
    function stop() { if (timer) clearTimeout(timer); if (typing) clearInterval(typing); timer = null; typing = null; }
    const api_ = {
      play() {
        if (reducedMotion) { clear(screen); frames.forEach((f) => screen.append(h("div", { class: cls(f.stream) }, f.text))); i = frames.length; progress(); setBtn(); return; }
        if (i >= frames.length) { clear(screen); i = 0; }
        playing = true; setBtn(); step();
      },
      pause() { playing = false; stop(); setBtn(); },
      toggle() { playing ? api_.pause() : api_.play(); },
      restart() { stop(); clear(screen); i = 0; progress(); playing = false; api_.play(); },
      destroy() { playing = false; stop(); },
      total,
    };
    setBtn();
    return api_;
  }
  function stopPlayer() { if (S.player) { S.player.destroy(); S.player = null; } }

  // ───────────────────────────────────────────────────────── Hermes
  function hermesUrl(conf) {
    if (!conf) return null;
    if (conf.url) return conf.url;
    return location.protocol + "//" + location.hostname + ":" + conf.port + "/";
  }
  function setupHermesLinks() {
    const st = S.status;
    if (!st) return;
    const dash = hermesUrl(st.hermes.dashboard);
    const app = hermesUrl(st.hermes.webapp);
    $("h-dash-open").href = dash; $("h-dash-url").textContent = dash;
    $("h-app-open").href = app; $("h-app-url").textContent = app;
    const mark = (id, conf) => {
      const el = $(id);
      if (conf.up === undefined) { el.textContent = ""; return; }
      el.dataset.up = conf.up ? "true" : "false";
      el.textContent = conf.up ? "● en línea" : "● no disponible";
      el.title = conf.detail || "";
    };
    mark("h-dash-up", st.hermes.dashboard);
    mark("h-app-up", st.hermes.webapp);
    $("h-app-hint").hidden = st.hermes.webapp.up !== false;
    setupScreens(st);
  }

  // ── Pantallas (demo en vivo) ──────────────────────────────────────
  function screenUrl(conf) {
    if (!conf || !conf.port) return null;
    return location.protocol + "//" + location.hostname + ":" + conf.port + "/";
  }
  function novncUrl(base) {
    return base.replace(/\/$/, "") + "/vnc.html?autoconnect=1&resize=scale&reconnect=1&view_only=1";
  }
  const SCREENS = {
    browser: { conf: () => S.status && S.status.screens && S.status.screens.browser, embed: (u) => novncUrl(u) },
    caido: { conf: () => S.status && S.status.screens && S.status.screens.caido_director,
             embed: (u) => novncUrl(u) },  // noVNC del director: Caido manejándose solo
  };
  function setupScreens(st) {
    const sc = st.screens || {};
    const mk = (id, conf) => {
      const el = $(id);
      if (!el) return;
      if (!conf || conf.up === undefined) { el.textContent = ""; return; }
      el.dataset.up = conf.up ? "true" : "false";
      el.textContent = conf.up ? "● en línea" : "● no disponible";
      el.title = conf.detail || "";
    };
    mk("sc-browser-up", sc.browser);
    mk("sc-caido-up", sc.caido_director);
    const bu = screenUrl(sc.browser), cu = screenUrl(sc.caido_director), ci = screenUrl(sc.caido);
    if (bu) { $("sc-browser-open").href = novncUrl(bu); $("sc-browser-url").textContent = bu; }
    if (cu) { $("sc-caido-url").textContent = "dirigido · " + cu; }
    else { $("sc-caido-url").textContent = ""; }
    if (ci) { $("sc-caido-open").href = ci; }   // "Abrir ↗" = Caido interactivo real
  }
  function toggleScreen(which, force) {
    const def = SCREENS[which];
    const base = screenUrl(def.conf());
    const frame = $("sc-" + which + "-frame");
    const btn = document.querySelector('[data-screen="' + which + '"][data-act="toggle"]');
    const showing = frame.querySelector("iframe");
    if (showing && force !== true) {
      if (which === "caido") S.caidoFrame = null;
      frame.querySelector("iframe").remove();
      $("sc-" + which + "-hint").hidden = false;
      btn.setAttribute("aria-pressed", "false"); btn.textContent = "Mostrar";
      return;
    }
    if (!base) { toast("err", "No disponible", "La pantalla de " + which + " no está publicada."); return; }
    if (showing) return;
    $("sc-" + which + "-hint").hidden = true;
    const ifr = h("iframe", { src: def.embed(base), title: which, referrerpolicy: "no-referrer",
      allow: "fullscreen", loading: "lazy" });
    frame.append(ifr);
    if (which === "caido") { S.caidoFrame = ifr; S.caidoBase = base; S.caidoRoute = "http-history"; }
    btn.setAttribute("aria-pressed", "true"); btn.textContent = "Ocultar";
  }
  function caidoRouteFor(tool) {
    const t = String(tool || "").toLowerCase();
    if (t.includes("caido_request") || t.includes("replay")) return "replay";
    if (t.includes("caido_automate") || t.includes("automate")) return "automate";
    if (t.includes("caido_intercept") || t.includes("intercept")) return "intercept";
    if (t.includes("caido")) return "http-history";
    return null;
  }
  function caidoFollow(tool) {
    if (!S.caidoFrame || !S.caidoBase) return;
    const follow = $("caido-follow");
    if (follow && !follow.checked) return;
    const route = caidoRouteFor(tool);
    if (!route || route === S.caidoRoute) return;
    S.caidoRoute = route;
    // cambio de solo-fragmento: navegación suave del iframe (sin recarga)
    S.caidoFrame.src = S.caidoBase.replace(/\/$/, "") + "/#/" + route;
  }
  function renderPantActions() {
    const feed = $("pant-feed");
    if (!feed) return;
    const o = currentOoda();
    const badge = $("pant-phase");
    badge.dataset.phase = o ? o.phase : "";
    badge.textContent = o ? (o.phase + " · " + o.step) : "—";
    const running = [...S.calls.values()].filter((c) => !c.result && c.ev.ts);
    $("pant-now").textContent = running.length
      ? ("ejecutando: " + running.map((c) => c.ev.tool_display || c.ev.tool).join(", "))
      : (o ? o.text : (S.sid ? "en curso" : "sin sesión activa"));
    // feed: OODA + tool-calls (con estado) + razonamiento, lo más reciente abajo
    const items = S.events.filter((e) => ["ooda", "tool.call", "reasoning"].includes(e.kind)).slice(-60);
    clear(feed);
    if (!items.length) { feed.append(h("li", { class: "feed__empty" }, "Sin acciones todavía.")); return; }
    for (const ev of items) {
      if (ev.kind === "ooda") {
        feed.append(h("li", { class: "pact pact--ooda" },
          h("span", { class: "tm" }, fmtTime(ev.ts)),
          h("span", { class: "phase-badge", "data-phase": ev.phase }, ev.phase + " · " + ev.step),
          h("span", { class: "bd" }, ev.text || "")));
      } else if (ev.kind === "reasoning") {
        feed.append(h("li", { class: "pact pact--think" },
          h("span", { class: "tm" }, fmtTime(ev.ts)),
          h("span", { class: "bd muted" }, "∴ " + oneLine(ev.text, 200))));
      } else {
        const c = S.calls.get(ev.call_id) || { ev, result: null };
        const st = statusText(c);
        feed.append(h("li", { class: "pact" },
          h("span", { class: "tm" }, fmtTime(ev.ts)),
          h("span", { class: "bd" },
            h("span", { class: "t cat", "data-cat": ev.category }, ev.tool_display || ev.tool),
            h("span", { class: "c" }, " " + oneLine(ev.summary, 220))),
          st.running ? h("span", { class: "st " + st.cls, "data-since": ev.ts }, fmtDur(now() - ev.ts))
                     : h("span", { class: "st " + st.cls }, st.text)));
      }
    }
    feed.scrollTop = feed.scrollHeight;
  }
  function renderScreens() {
    if (S.status) setupScreens(S.status);
    renderPantActions();
    // auto-muestra las dos pantallas si están disponibles (lo esperable al abrir la pestaña)
    // (misma fuente que "Mostrar ambas": la pantalla de Caido es el director, no el Caido real)
    mountAvailableScreens();
    syncBothBtn();
  }
  document.querySelectorAll("[data-screen]").forEach((b) => b.addEventListener("click", () => {
    const which = b.dataset.screen;
    if (b.dataset.act === "toggle") return toggleScreen(which);
    if (b.dataset.act === "full") {
      const frame = $("sc-" + which + "-frame");
      if (!frame.querySelector("iframe")) toggleScreen(which, true);
      if (frame.requestFullscreen) frame.requestFullscreen().catch(() => {});
    }
  }));
  // ── Modo escenario (proyectar en una charla) ──────────────────────
  // Oculta la consola (barra, sesiones, franja) y deja: cabecera con la fase OODA en grande +
  // navegador y Caido lado a lado + ticker de acciones. Todo con clases (CSP estricta).
  function screenUp(which) {
    const conf = SCREENS[which].conf();
    return !!(conf && conf.up && screenUrl(conf));
  }
  function mountAvailableScreens() {
    for (const which of ["browser", "caido"]) {
      if (screenUp(which) && !$("sc-" + which + "-frame").querySelector("iframe")) toggleScreen(which, true);
    }
  }
  function renderStage() {
    if (!S.stage) return;
    const o = currentOoda();
    const badge = $("stage-phase");
    badge.dataset.phase = o ? o.phase : "";
    badge.textContent = o ? (o.phase + " · " + o.step) : "—";
    $("stage-text").textContent = o ? (o.text || "") : (S.sid ? "En curso" : "Esperando actividad del agente…");
    const run = $("stage-run");
    const running = [...S.calls.values()].filter((c) => !c.result && c.ev.ts)
      .sort((a, b) => b.ev.ts - a.ev.ts);
    clear(run);
    if (running.length) {
      const c = running[0];
      run.append(
        h("span", { class: "stage-head__dot" }),
        h("span", { class: "stage-head__tool cat", "data-cat": c.ev.category }, c.ev.tool_display || c.ev.tool),
        h("span", { class: "stage-head__clock", "data-since": c.ev.ts }, fmtDur(now() - c.ev.ts)),
        ...(running.length > 1 ? [h("span", { class: "stage-head__more" }, "+" + (running.length - 1))] : []));
    } else {
      run.append(h("span", { class: "stage-head__idle" }, "sin tools en curso"));
    }
    mountAvailableScreens();
  }
  function enterStage() {
    if (S.stage) return;
    if (S.view !== "pantallas") showView("pantallas");
    S.stage = true;
    document.body.classList.add("is-stage");
    mountAvailableScreens();
    renderPantActions();
    renderStage();
    S.stageTimer = setInterval(renderStage, 1000);
    S.stageFs = false;
    const root = document.documentElement;
    if (root.requestFullscreen && !document.fullscreenElement) {
      root.requestFullscreen().then(() => { S.stageFs = true; }).catch(() => { /* sin fullscreen: sigue en escenario */ });
    }
  }
  function exitStage() {
    if (!S.stage) return;
    S.stage = false;
    document.body.classList.remove("is-stage");
    clearInterval(S.stageTimer);
    if (S.stageFs && document.fullscreenElement) document.exitFullscreen().catch(() => {});
    S.stageFs = false;
    renderPantActions();
  }
  // «Mostrar ambas»: monta navegador y Caido a la vez (o los oculta si ya están los dos)
  function syncBothBtn() {
    const both = ["browser", "caido"].every((w) => $("sc-" + w + "-frame").querySelector("iframe"));
    const btn = $("screens-both");
    btn.setAttribute("aria-pressed", both ? "true" : "false");
    btn.textContent = both ? "Ocultar ambas" : "Mostrar ambas";
  }
  $("screens-both").addEventListener("click", () => {
    const shown = ["browser", "caido"].filter((w) => $("sc-" + w + "-frame").querySelector("iframe"));
    if (shown.length === 2) { shown.forEach((w) => toggleScreen(w)); syncBothBtn(); return; }
    const avail = ["browser", "caido"].filter((w) => screenUrl(SCREENS[w].conf()));
    if (!avail.length) { toast("err", "No disponible", "Ni el navegador ni Caido están publicados todavía."); return; }
    avail.forEach((w) => toggleScreen(w, true));
    syncBothBtn();
  });
  document.querySelectorAll('[data-screen][data-act="toggle"]').forEach((b) => b.addEventListener("click", syncBothBtn));
  $("stage-enter").addEventListener("click", enterStage);
  $("stage-exit").addEventListener("click", exitStage);
  document.addEventListener("fullscreenchange", () => {
    // Esc en fullscreen lo consume el navegador: al salir de fullscreen salimos también del escenario
    if (S.stage && S.stageFs && !document.fullscreenElement) { S.stageFs = false; exitStage(); }
  });
  document.addEventListener("keydown", (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(INPUT|SELECT|TEXTAREA)$/.test(t.tagName))) return;
    if (e.key === "Escape" && S.stage) { e.preventDefault(); exitStage(); }
    else if ((e.key === "e" || e.key === "E") && !S.stage) { e.preventDefault(); enterStage(); }
  });

  document.querySelectorAll("[data-embed]").forEach((b) => b.addEventListener("click", () => {
    const st = S.status;
    if (!st) return;
    const which = b.dataset.embed;
    const url = which === "dash" ? hermesUrl(st.hermes.dashboard) : hermesUrl(st.hermes.webapp);
    $("h-frame").src = url;
    $("h-embed-title").textContent = (which === "dash" ? "Dashboard · " : "Webapp · ") + url;
    $("h-embed").hidden = false;
  }));
  $("h-embed-close").addEventListener("click", () => { $("h-frame").src = "about:blank"; $("h-embed").hidden = true; });

  // ───────────────────────────────────────────────────────── toasts
  function toast(kind, title, text, onClick) {
    const el = h("div", { class: "toast toast--" + kind, role: "status" }, h("b", null, title), oneLine(text, 160));
    el.addEventListener("click", () => { el.remove(); if (onClick) onClick(); });
    $("toasts").append(el);
    setTimeout(() => el.remove(), 12000);
  }

  // ───────────────────────────────────────────────────────── stream en vivo
  function onEvent(ev) {
    if (ev.kind === "web.request") {
      S.web.push(ev);
      if (S.web.length > 400) S.web.splice(0, S.web.length - 300);
      if (S.view === "copilot") renderWeb();
      return;
    }
    S.lastActivity = now();
    if (ev.session_id && ev.session_id === S.sid) {
      if (S.loading) { S.pending.push(ev); }
      else if (ev.seq > S.lastSeq) {
        S.events.push(ev); S.lastSeq = ev.seq;
        if (S.events.length > 6000) S.events.splice(0, 1000);
        appendTermEvent(ev);
        if (!termFilterActive()) $("t-count").textContent = S.events.length + " eventos";
        if (ev.kind === "ooda") renderStrip();
        markCopilotDirty();
        markTraceDirty();
        if (S.view === "pantallas") renderPantActions();
      }
    }
    if (isFinding(ev)) pocRefresh();
    refreshSessionsSoon();
    updateLive();
  }

  function openStream(after) {
    const es = new EventSource("/api/stream?after=" + encodeURIComponent(after));
    es.addEventListener("ev", (e) => {
      try { onEvent(JSON.parse(e.data)); } catch (_) { /* evento malformado: se ignora */ }
    });
  }

  // ───────────────────────────────────────────────────────── arranque
  async function boot() {
    applyTermFilters();
    await loadStatus();
    await loadSessions();
    await Promise.all([loadWebTail(), loadPocs()]);
    if (!S.sid) {
      term.append(h("div", { class: "term__empty" },
        "Esperando al agente. En cuanto un engagement ejecute su primer paso verás aquí, en vivo, " +
        "cada línea OODA, su razonamiento y cada comando con su salida."));
    }
    showView(location.hash.slice(1) || "terminal");
    openStream(S.status ? S.status.max_seq : 0);
    loadSeverities();
    setInterval(loadSessions, 3000);
    setInterval(loadStatus, 5000);
    setInterval(loadPocs, 8000);
    setInterval(loadSeverities, 15000);
    setInterval(() => { if (S.view === "traces" && traceDirty) loadTrace(); }, 2000);
  }
  boot();
})();
