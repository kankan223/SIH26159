/* SecureMailScope — SPA logic (vanilla JS, no external dependencies) */
"use strict";

/* ------------------------------------------------------------- theme (light/dark + print) */
/* Applies the saved theme before first paint to avoid a flash of the wrong theme. */
(function initTheme() {
  let t = null;
  try { t = localStorage.getItem("sms-theme"); } catch { /* storage unavailable */ }
  if (t === "light" || t === "dark") {
    document.documentElement.setAttribute("data-theme", t);
    document.documentElement.classList.add("theme-init");
  }
})();

function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

function applyTheme(t, persist) {
  document.documentElement.setAttribute("data-theme", t);
  if (persist) { try { localStorage.setItem("sms-theme", t); } catch { /* ignore */ } }
  const btn = $("#themeToggle");
  if (btn) {
    btn.textContent = t === "light" ? "🌙 Dark" : "☀ Light";
    btn.setAttribute("aria-pressed", String(t === "light"));
    btn.title = "Switch to " + (t === "light" ? "dark" : "light") + " theme (also used for printing)";
  }
  if (S.result) renderDashboard();   // canvas charts are painted with theme colors
}

function toggleTheme() {
  applyTheme(currentTheme() === "light" ? "dark" : "light", true);
}

/* ------------------------------------------------------------------ state */
const S = {
  scenarios: [],
  result: null,
  scenarioSel: null,
  uploadFile: null,
  resolved: new Set(),
  sessFilter: "ALL",
  findFilter: "ALL",
  drawerSession: null,
  settings: { data_mode: "evaluation", retention: "session" },
  audit: [],
  auditSearch: "",
  auditFilter: "ALL",
  auditLimit: 50,   // windowed pagination: events shown in the panel
};

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));
const esc = (x) => String(x ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLOR = { CRITICAL: "#e5484d", HIGH: "#f76b15", MEDIUM: "#f5d90a", LOW: "#30a46c" };
const RISK_COLOR = { SECURE: "#30a46c", "LOW RISK": "#30a46c", "MODERATE RISK": "#f5d90a", "HIGH RISK": "#f76b15", CRITICAL: "#e5484d" };
const SEV_PENALTY = { CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 };

/* deep-link driver: /?autostart=<id>&view=<view>&session=<id>&report=1
   Jumps straight to any point of the flow — used by the test harness and saved views. */
const QS = new URLSearchParams(location.search);

/* ------------------------------------------------------------------ boot */
document.addEventListener("DOMContentLoaded", async () => {
  bindNav();
  bindAnalysis();
  bindDrawer();
  bindFilters();
  const tt = $("#themeToggle");
  if (tt) tt.addEventListener("click", toggleTheme);
  applyTheme(currentTheme(), false);   // sync toggle label with the pre-paint theme
  bindModal();
  bindSettings();
  loadSettings();
  try {
    const r = await fetch("/api/scenarios");
    const d = await r.json();
    S.scenarios = d.scenarios || [];
  } catch { S.scenarios = []; }
  buildScenarioCards();
  buildTopScenarioSelect();
  applyModeGate();

  // deep-link autostart: select + run scenario on load (library access only)
  const auto = QS.get("autostart");
  if (auto && !modeGateActive() && S.scenarios.some(s => s.id === auto)) {
    S.scenarioSel = auto;
    S.pendingView = QS.get("view");
    if (QS.has("report")) S.autoReport = true;
    $$('.scen-card').forEach((x, i) => x.classList.toggle("selected", !!(S.scenarios[i] && S.scenarios[i].id === auto)));
    $("#btnAnalyzeScenario").disabled = false;
    $("#scenHint").textContent = "Deep-link: " + auto;
    runScenario(auto, !QS.has("animated"));
  }
});

/* ------------------------------------------------------------------ nav */
function bindNav() {
  const goView = (name) => {
    const b = $$("nav button").find(x => x.dataset.view === name);
    if (b) b.click();
  };
  $$("nav button").forEach(b => b.addEventListener("click", () => {
    $$("nav button").forEach(x => x.classList.toggle("active", x === b));
    $$(".view").forEach(v => v.classList.toggle("active", v.id === "view-" + b.dataset.view));
  }));
  const go = $("#goAnalysis");
  if (go) go.addEventListener("click", () => goView("analysis"));
  // keyboard shortcuts: 1–6 switch views (ignored while typing in inputs)
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input, select, textarea") || e.ctrlKey || e.metaKey || e.altKey) return;
    const views = ["dashboard", "analysis", "sessions", "findings", "remediation", "report", "settings"];
    const n = parseInt(e.key, 10);
    if (n >= 1 && n <= views.length) goView(views[n - 1]);
  });
}

/* ------------------------------------------------------------------ analysis page */
function bandClass(band) {
  if (band === "SECURE" || band === "LOW RISK") return "secure";
  if (band === "MODERATE RISK") return "warn";
  if (band === "HIGH RISK") return "risk";
  if (band === "CRITICAL") return "crit";
  return "outline";
}

function buildScenarioCards() {
  const grid = $("#scenGrid");
  grid.innerHTML = "";
  for (const sc of S.scenarios) {
    const b = document.createElement("button");
    b.className = "scen-card";
    const band = sc.expected_band
      ? `<div><span class="scen-band ${bandClass(sc.expected_band)}">EXPECTED ${esc(sc.expected_band)} · ${sc.expected_score}/100</span></div>`
      : "";
    b.innerHTML = `<b>${esc(sc.name)}</b><span>${esc(sc.description)}</span>
      <div class="file">${esc(sc.file_label)} · ${esc(sc.size_hint)}</div>${band}`;
    b.addEventListener("click", () => {
      S.scenarioSel = sc.id;
      $$(".scen-card").forEach(x => x.classList.toggle("selected", x === b));
      $("#btnAnalyzeScenario").disabled = false;
      $("#scenHint").textContent = `Selected: ${sc.name}`;
    });
    grid.appendChild(b);
  }
}

function buildTopScenarioSelect() {
  const sel = $("#topScenario");
  sel.innerHTML = "";
  for (const sc of S.scenarios) {
    const o = document.createElement("option");
    o.value = sc.id; o.textContent = sc.name;
    sel.appendChild(o);
  }
  sel.addEventListener("change", async () => {
    S.scenarioSel = sel.value;
    $$(".scen-card").forEach((x, i) => x.classList.toggle("selected", S.scenarios[i] && S.scenarios[i].id === sel.value));
    await runScenario(sel.value);
  });
}

function bindAnalysis() {
  const fileInput = $("#pcapFile");
  const drop = $("#dropZone");

  fileInput.addEventListener("change", () => fileInput.files[0] && setUpload(fileInput.files[0]));
  ["dragover", "dragleave", "drop"].forEach(ev => drop.addEventListener(ev, (e) => {
    e.preventDefault();
    drop.classList.toggle("hover", ev === "dragover");
    if (ev === "drop" && e.dataTransfer.files[0]) setUpload(e.dataTransfer.files[0]);
  }));

  $("#btnAnalyzeUpload").addEventListener("click", () => analyzeUpload());
  $("#btnAnalyzeScenario").addEventListener("click", () => {
    if (modeGateActive()) {
      $("#scenHint").textContent = "Blocked: LIVE data mode — operator-supplied captures only.";
      return;
    }
    S.scenarioSel && runScenario(S.scenarioSel);
  });

  const exportJson = () => exportReport("json");
  const exportHtml = () => exportReport("html");
  $("#btnExportJson").addEventListener("click", exportJson);
  $("#btnExportHtml").addEventListener("click", exportHtml);
  $("#btnExportJson2").addEventListener("click", exportJson);
  $("#btnExportHtml2").addEventListener("click", exportHtml);
}

/* ------------------------------------------------------------------ confirm modal */
function bindModal() {
  $("#modalCancel").addEventListener("click", () => resolveConfirm(false));
  $("#modalConfirm").addEventListener("click", () => resolveConfirm(true));
  $("#modalBack").addEventListener("click", (e) => {
    if (e.target === $("#modalBack")) resolveConfirm(false);   // backdrop click
  });
  document.addEventListener("keydown", (e) => {
    if (!$("#modalBack").classList.contains("open")) return;
    if (e.key === "Escape") resolveConfirm(false);
    if (e.key === "Enter") { e.preventDefault(); resolveConfirm(true); }
  });
}

let _confirmResolve = null;
function resolveConfirm(v) {
  if (!_confirmResolve) return;
  $("#modalBack").classList.remove("open");
  const r = _confirmResolve;
  _confirmResolve = null;
  r(v);
}

/* confirmDialog({title, message, confirmLabel}) → Promise<boolean> */
function confirmDialog(opts) {
  return new Promise((resolve) => {
    if (_confirmResolve) resolveConfirm(false);   // collapse any pending dialog
    _confirmResolve = resolve;
    $("#modalTitle").textContent = opts.title || "Confirm action";
    $("#modalMsg").innerHTML = opts.message || "";   // callers pass escaped content
    $("#modalConfirm").textContent = opts.confirmLabel || "Confirm";
    $("#modalBack").classList.add("open");
    $("#modalCancel").focus();
  });
}

/* ------------------------------------------------------------------ settings */
let retentionMsg = "";   // transient action message; survives the async re-render
function setRetentionHint(t) {
  retentionMsg = t;
  const el = $("#retentionHint");
  if (el) el.textContent = t;
}

function bindSettings() {
  $("#setLiveMode").addEventListener("change", async (e) => {
    const goingLive = e.target.checked;
    if (goingLive) {
      const ok = await confirmDialog({
        title: "Switch to LIVE data mode",
        message: "In <b>LIVE</b> mode the engine processes <b>operator-supplied captures only</b> — " +
          "the curated capture library is disabled and the capture selector is locked until you switch back.<br><br>Continue?",
        confirmLabel: "Switch to LIVE",
      });
      if (!ok) { e.target.checked = false; return; }   // revert the switch
    }
    await saveSettings({ data_mode: goingLive ? "live" : "evaluation" });
  });
  $("#setRetention").addEventListener("change", async (e) => {
    const newValue = e.target.value;
    const current = S.settings.retention || "session";
    // warn only when the new window would sweep existing artifacts
    const wouldSweep = await wouldSweepArtifacts(newValue);
    if (wouldSweep > 0) {
      const ok = await confirmDialog({
        title: "Change retention window",
        message: `Reducing the retention window to <b>${esc(ttlLabel(newValue))}</b> will permanently remove ` +
          `<b>${wouldSweep}</b> generated report artifact${wouldSweep === 1 ? "" : "s"} right now. This cannot be undone.<br><br>Continue?`,
        confirmLabel: "Change & sweep",
      });
      if (!ok) { e.target.value = current; return; }   // revert the select
    }
    retentionMsg = "";   // new window → resume showing the window label
    await saveSettings({ retention: newValue });
  });
  // audit trail exports (download + hint; the export itself is audited server-side)
  const doAuditExport = async (fmt) => {
    const hint = $("#auditExportHint");
    try {
      const res = await fetch("/api/audit/export?format=" + fmt);
      if (!res.ok) { hint.textContent = "Export failed."; return; }
      const blob = await res.blob();
      triggerDownload(blob, res.headers.get("Content-Disposition")
        ?.match(/filename=(.+)/)?.[1] || `securemailscope_audit.${fmt}`);
      hint.textContent = `Exported ${fmt.toUpperCase()} — ${new Date().toLocaleTimeString()}`;
      refreshAudit();   // the export event itself lands in the trail
    } catch (e) {
      hint.textContent = "Export failed: " + e.message;
    }
  };
  $("#btnAuditJson").addEventListener("click", () => doAuditExport("json"));
  $("#btnAuditCsv").addEventListener("click", () => doAuditExport("csv"));
  const btnStix = $("#btnExportStix");
  if (btnStix) btnStix.addEventListener("click", () => exportSiem("stix"));
  const btnCsvF = $("#btnExportFindingsCsv");
  if (btnCsvF) btnCsvF.addEventListener("click", () => exportSiem("csv"));
  const btnCmp = $("#btnCompare");
  if (btnCmp) btnCmp.addEventListener("click", () => runCompare());

  // audit panel search + category filters (client-side, instant)
  $("#auditSearch").addEventListener("input", (e) => {
    S.auditSearch = e.target.value.toLowerCase();
    renderAudit();
  });
  $("#auditFilters").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    $$("#auditFilters button").forEach(x => x.classList.toggle("active", x === b));
    S.auditFilter = b.dataset.f;
    S.auditLimit = 50;   // filter changes reset the window
    renderAudit();
  });

  $("#btnClearReports").addEventListener("click", async () => {
    const n = await countArtifacts();
    const ok = await confirmDialog({
      title: "Clear report store",
      message: n > 0
        ? `Permanently remove all <b>${n}</b> generated report artifact${n === 1 ? "" : "s"} from the report store? This cannot be undone.`
        : "The report store is already empty. Clear it anyway?",
      confirmLabel: "Delete artifacts",
    });
    if (!ok) return;
    const btn = $("#btnClearReports");
    btn.disabled = true;
    try {
      const r = await fetch("/api/reports/clear", { method: "POST" });
      const d = await r.json();
      setRetentionHint(`Removed ${d.removed} artifact(s).`);
      if (d.audit) { S.audit = d.audit; S.auditLimit = 50; renderAudit(); }   // new event → reset window
    } catch (e) {
      setRetentionHint("Clear failed: " + e.message);
    } finally {
      btn.disabled = false;
      loadSettings();
    }
  });
}

async function loadSettings() {
  try {
    const r = await fetch("/api/settings");
    const d = await r.json();
    if (d.settings) S.settings = d.settings;
    if (d.audit) { S.audit = d.audit; S.auditLimit = 50; }
  } catch { /* keep defaults */ }
  renderSettings();
}

async function saveSettings(patch) {
  try {
    const r = await fetch("/api/settings", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(patch),
    });
    const d = await r.json();
    if (d.settings) S.settings = d.settings;
    if (d.audit) { S.audit = d.audit; S.auditLimit = 50; }
    if (d.error) setRetentionHint(d.error);
  } catch (e) {
    setRetentionHint("Save failed: " + e.message);
  }
  renderSettings();
}

function modeGateActive() {
  return S.settings.data_mode === "live";
}

/* apply the data-mode gate to the already-rendered capture library */
function applyModeGate() {
  const gate = modeGateActive();
  $$(".scen-card").forEach(b => {
    b.classList.toggle("gated", gate);
    b.disabled = gate;
    b.title = gate ? "Disabled in LIVE data mode — switch to Evaluation in Settings." : "";
  });
  const sel = $("#topScenario");
  if (sel) sel.disabled = gate;
  if (gate) $("#scenHint").textContent = "Capture library disabled in LIVE data mode (Settings).";
}

function renderSettings() {
  const live = modeGateActive();
  const sw = $("#setLiveMode");
  if (sw) {
    sw.checked = live;
    const note = $("#modeNote");
    note.innerHTML = live
      ? `<b>LIVE</b> · operator-supplied captures only — <span class="dot-ok">●</span> library access disabled`
      : `<b>EVALUATION</b> · curated mail-security capture library enabled — <span class="dot-ok">●</span> uploads fully parsed on-engine (PCAP → TCP flows → TLS/X.509)`;
    $("#setRetention").value = S.settings.retention || "session";
    $("#setDeployment").textContent = live ? "SOC appliance — inline collection" : "Analyst workstation — evaluation profile";
    $("#setVersion").textContent = "1.0 (engine " + ENGINE_BUILD + ")";
  }
  if (S.scenarios.length) applyModeGate();
  renderReportStore();
  renderAudit();
}

/* pull the latest audit events without touching other settings state */
async function refreshAudit() {
  try {
    const r = await fetch("/api/settings");
    const d = await r.json();
    if (d.audit) { S.audit = d.audit; S.auditLimit = 50; renderAudit(); }
  } catch { /* non-fatal */ }
}

/* audit event → filter category */
function auditCategory(ev) {
  if (ev.endsWith("_rejected")) return "REJECTED";
  if (ev === "mode_change" || ev === "retention_change") return "POLICY";
  if (ev === "analysis_run" || ev === "session_inspect" || ev === "comparison_run") return "ANALYSIS";
  if (ev === "report_export" || ev === "reports_cleared" || ev === "audit_export" || ev === "siem_export") return "REPORTS";
  return "POLICY";   // future event types default to policy visibility
}

function renderAudit() {
  const box = $("#auditBox");
  if (!box) return;
  const q = S.auditSearch;
  const rows = (S.audit || []).filter(e => {
    if (S.auditFilter !== "ALL" && auditCategory(e.event || "") !== S.auditFilter) return false;
    if (!q) return true;
    return `${e.ts || ""} ${e.event || ""} ${e.detail || ""}`.toLowerCase().includes(q);
  });
  const total = (S.audit || []).length;
  const shown = rows.slice(0, S.auditLimit);   // windowed pagination, newest first
  const hidden = rows.length - shown.length;
  box.innerHTML = shown.map(e => {
    const ev = String(e.event || "");
    const cls = ev.endsWith("_rejected") ? "rejected" : ev;
    const match = q && `${e.ts || ""} ${e.event || ""} ${e.detail || ""}`.toLowerCase().includes(q);
    return `<div class="audit-row${match ? " match" : ""}">
      <span class="ts">${esc(e.ts || "")}</span>
      <span class="ev ${esc(cls)}">${esc(ev)}</span>
      <span class="dt" title="${esc(e.detail || "")}">${esc(e.detail || "")}</span>
    </div>`;
  }).join("")
    || (total ? `<div class="empty">No events match this filter (${total} in trail).</div>`
              : `<div class="empty">No audit events recorded yet.</div>`);
  if (hidden > 0) {
    const more = document.createElement("button");
    more.className = "btn small audit-more";
    more.textContent = `Show ${Math.min(50, hidden)} older event${hidden === 1 ? "" : "s"} (${hidden} hidden)`;
    more.addEventListener("click", () => { S.auditLimit += 50; renderAudit(); });
    box.appendChild(more);
  }
  const hint = $("#auditExportHint");
  if (hint) {
    const scope = (S.auditFilter === "ALL" && !q) ? "Full trail" : `${rows.length} of ${total} shown`;
    hint.textContent = `${scope} — exports always include the full trail.`;
  }
}

function renderReportStore() {
  const tb = $("#repStoreRows");
  if (!tb) return;
  fetch("/api/settings").then(r => r.json()).then(d => {
    const rows = d.reports || [];
    tb.innerHTML = rows.map(x => `
      <tr>
        <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(x.name)}">${esc(x.name)}</td>
        <td><span class="chip outline">${esc(x.kind.toUpperCase())}</span></td>
        <td class="mono">${(x.size_bytes / 1024).toFixed(1)} KB</td>
        <td class="mono dim">${new Date(x.mtime * 1000).toLocaleString()}</td>
      </tr>`).join("") || `<tr><td colspan="4" class="empty">No report artifacts on disk.</td></tr>`;
    const ttl = { session: "Session only", "7d": "7 days", "30d": "30 days", "90d": "90 days", forever: "Forever" }[S.settings.retention] || "Session only";
    $("#retentionHint").textContent = retentionMsg || `Retention window: ${ttl}`;
  }).catch(() => {});
}

/* count artifacts currently on disk (for confirmation copy) */
async function countArtifacts() {
  try {
    const r = await fetch("/api/settings");
    const d = await r.json();
    return (d.reports || []).length;
  } catch { return 0; }
}

/* how many artifacts would a switch to `newValue` sweep right now? (0 = none) */
async function wouldSweepArtifacts(newValue) {
  const ttl = { session: 0, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, forever: -1 }[newValue];
  if (ttl === -1) return 0;   // forever never sweeps
  try {
    const r = await fetch("/api/settings");
    const d = await r.json();
    const now = Date.now() / 1000;
    return (d.reports || []).filter(x => now - x.mtime > ttl).length;
  } catch { return 0; }
}

function ttlLabel(v) {
  return { session: "Session only", "7d": "7 days", "30d": "30 days", "90d": "90 days", forever: "Forever" }[v] || v;
}

const ENGINE_BUILD = "2026.09";

/* ------------------------------------------------------------------ analysis page */
function setUpload(f) {
  S.uploadFile = f;
  $("#fileInfo").textContent = `${f.name} · ${(f.size / 1024 / 1024).toFixed(2)} MB — ready for validation`;
  $("#btnAnalyzeUpload").disabled = false;
}

async function analyzeUpload() {
  if (!S.uploadFile) return;
  const fd = new FormData();
  fd.append("pcap", S.uploadFile);
  const btn = $("#btnAnalyzeUpload");
  const live = $("#termLive");
  btn.disabled = true;
  btn.classList.add("loading");
  if (live) live.style.display = "";
  termLine("Validating " + S.uploadFile.name + " …", "info");
  try {
    const r = await fetch("/api/analyze?mode=upload", { method: "POST", body: fd });
    const d = await r.json();
    if (!r.ok) { termLine("✗ " + (d.error || "validation failed"), "warn"); return; }
    termLine("✓ " + d.meta.upload_note, "ok");
    if (d.meta.parse_stats) {
      const ps = d.meta.parse_stats;
      termLine(`✓ Parsed ${ps.packets} packets → ${ps.tcp_flows} TCP flows → ${ps.sessions} mail/TLS session(s), ${ps.certificates_parsed} certificate(s) analyzed`, "ok");
      if (ps.sessions_truncated) termLine(`! Capture exceeded the session cap — showing the first ${ps.sessions}`, "warn");
    }
    ingest(d);
  } catch (e) {
    termLine("✗ Upload failed: " + e.message, "warn");
  } finally {
    btn.disabled = false;
    btn.classList.remove("loading");
    if (live) live.style.display = "none";
  }
}

async function runScenario(id, instant = false) {
  // simulated pipeline — short and honest (1.6s total; instant for deep-links)
  const lines = [
    ["Loading capture from dataset …", "info"],
    ["Detecting protocols (SMTP / IMAP / POP3) …", "info"],
    ["Reconstructing email sessions …", "info"],
    ["Analyzing STARTTLS / TLS handshakes …", "info"],
    ["Inspecting X.509 certificates …", "info"],
    ["Evaluating cryptographic posture …", "info"],
    ["Running anomaly analysis …", "info"],
    ["Applying AI-assisted prioritization …", "info"],
  ];
  $("#term").innerHTML = "";
  const btn = $("#btnAnalyzeScenario");
  const live = $("#termLive");
  btn.disabled = true;
  btn.classList.add("loading");
  if (live) live.style.display = "";
  for (const [txt, cls] of lines) {
    termLine(txt, cls);
    if (!instant) await sleep(150);
  }
  try {
    const r = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario_id: id }),
    });
    const d = await r.json();
    if (!r.ok) { termLine("✗ " + (d.error || "analysis failed"), "warn"); return; }
    termLine(`✓ Analysis complete — ${d.session_stats.total} sessions, posture ${d.risk.score}/100 (${d.risk.band}).`, "ok");
    ingest(d);
  } catch (e) {
    termLine("✗ Analysis failed: " + e.message, "warn");
  } finally {
    btn.disabled = !S.scenarioSel;
    btn.classList.remove("loading");
    if (live) live.style.display = "none";
  }
}

function termLine(text, cls) {
  const el = document.createElement("div");
  el.className = "line " + (cls || "");
  el.textContent = text;
  $("#term").appendChild(el);
  $("#term").scrollTop = $("#term").scrollHeight;
}

const sleep = (ms) => new Promise(res => setTimeout(res, ms));

/* ------------------------------------------------------------------ ingest */
function ingest(result) {
  S.result = result;
  S.resolved = new Set();
  renderDashboard();
  renderSessions();
  renderFindings();
  renderRemediation();
  // reporting page becomes usable once a result exists
  $("#repEmpty").style.display = "none";
  $("#repContent").style.display = "";
  // refresh the settings artifact table + audit trail so new runs/exports show immediately
  renderReportStore();
  loadComparePickers();
  refreshAudit();
  // land on the requested view (deep-link) or the dashboard, like a SOC product
  const viewBtn = S.pendingView ? $$("nav button").find(b => b.dataset.view === S.pendingView) : null;
  (viewBtn || $("nav button")).click();
  S.pendingView = null;
  if (QS.get("session")) openDrawer(QS.get("session"));
  if (S.autoReport) { S.autoReport = false; exportReport("html"); }
}

/* best-effort audit of client-side operator actions (server whitelists event types) */
function auditClient(event, detail) {
  try {
    fetch("/api/audit/record", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, detail }),
    }).then(r => r.json()).then(d => {
      if (d.ok && d.entry) { S.audit.unshift(d.entry); S.audit = S.audit.slice(0, 400); renderAudit(); }
    }).catch(() => {});
  } catch { /* audit must never break the UI */ }
}

/* --------------------------------------------- SOC/SIEM feed + capture comparison */
async function exportSiem(kind) {
  const btn = $(kind === "stix" ? "#btnExportStix" : "#btnExportFindingsCsv");
  if (btn) btn.disabled = true;
  try {
    const r = await fetch(`/api/findings/export?format=${kind}`);
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error(d.error || "export failed");
    }
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    const cd = (r.headers.get("Content-Disposition") || "").match(/filename=(.+)/);
    a.download = cd ? cd[1] : (kind === "stix" ? "securemailscope_stix.json" : "securemailscope_findings.csv");
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch (e) {
    alert("Export failed: " + e.message);
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function loadComparePickers() {
  const selA = $("#cmpBefore"), selB = $("#cmpAfter"), out = $("#cmpOut");
  if (!selA || !selB) return;
  try {
    const d = await (await fetch("/api/history")).json();
    const opts = d.history.map(h =>
      `<option value="${h.slot}">#${h.slot} · ${esc(h.name || h.scenario_id)} — ${h.score}/100 ${esc(h.band)}${h.source === "upload" ? " · upload" : ""}</option>`).join("");
    selA.innerHTML = opts || "<option value=\"\">— no history —</option>";
    selB.innerHTML = opts || "<option value=\"\">— no history —</option>";
    if (d.history.length >= 2) {
      selA.value = String(d.history.length - 2);
      selB.value = String(d.history.length - 1);
    }
    if (out && d.history.length < 2) out.innerHTML = `<div class="subtle">Run at least two analyses, then compare them here.</div>`;
  } catch { /* comparison is a convenience — never fatal */ }
}

async function runCompare() {
  const selA = $("#cmpBefore"), selB = $("#cmpAfter"), out = $("#cmpOut");
  if (!selA || !selB || !out) return;
  if (selA.value === "" || selB.value === "") return;
  if (selA.value === selB.value) { out.innerHTML = `<div class="subtle">Select two different snapshots.</div>`; return; }
  out.innerHTML = `<div class="subtle">Comparing…</div>`;
  try {
    const r = await fetch("/api/compare", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: +selA.value, b: +selB.value }) });
    const d = await r.json();
    if (!r.ok) { out.innerHTML = `<div class="subtle">${esc(d.error || "comparison failed")}</div>`; return; }
    const deltaCls = d.score_delta >= 0 ? "cmp-delta-pos" : "cmp-delta-neg";
    const rows = [];
    rows.push(`<div class="cmp-line"><span class="cmp-id">posture</span><span><b>${d.before.score}/100 ${esc(d.before.band)}</b> → <b>${d.after.score}/100 ${esc(d.after.band)}</b> <span class="${deltaCls}">(${d.score_delta >= 0 ? "+" : ""}${d.score_delta})</span></span></div>`);
    const sev = Object.entries(d.counts_delta).filter(([, v]) => v).map(([k, v]) => `${k} ${v > 0 ? "+" : ""}${v}`).join(" · ");
    if (sev) rows.push(`<div class="cmp-line"><span class="cmp-id">severity</span><span>${esc(sev)}</span></div>`);
    if (d.resolved_findings.length) rows.push(`<div class="cmp-line"><span class="cmp-id">resolved</span><span>${d.resolved_findings.map(f => `${esc(f.rule_id)} ${esc(f.title)}`).join(" · ")}</span></div>`);
    if (d.new_findings.length) rows.push(`<div class="cmp-line"><span class="cmp-id">new</span><span>${d.new_findings.map(f => `${esc(f.rule_id)} ${esc(f.title)}`).join(" · ")}</span></div>`);
    const changed = d.session_changes.filter(x => x.change === "changed");
    if (changed.length) rows.push(`<div class="cmp-line"><span class="cmp-id">sessions</span><span>${changed.slice(0, 6).map(x => `${esc(x.id)} ${x.risk_before}→${x.risk_after}`).join(" · ")}${changed.length > 6 ? ` +${changed.length - 6} more` : ""}</span></div>`);
    if (d.ml_delta.before !== d.ml_delta.after) rows.push(`<div class="cmp-line"><span class="cmp-id">ml outliers</span><span>${d.ml_delta.before} → ${d.ml_delta.after}</span></div>`);
    out.innerHTML = rows.join("");
  } catch (e) {
    out.innerHTML = `<div class="subtle">Comparison failed: ${esc(e.message)}</div>`;
  }
}

/* ------------------------------------------------------------------ dashboard */
function renderDashboard() {
  const r = S.result;
  if (!r) return;
  $("#dashEmpty").style.display = "none";
  $("#dashContent").style.display = "";
  const risk = r.risk, st = r.session_stats, c = risk.counts;

  animateGauge("gaugeCanvas", "gaugeScore", risk.score);
  updateTopChip(risk.score, risk.band);
  const band = $("#postureBand");
  band.textContent = risk.band;
  band.className = "status " + (risk.band === "SECURE" || risk.band === "LOW RISK" ? "secure" : risk.band === "MODERATE RISK" ? "warn" : "atrisk");
  $("#postureMeta").textContent = `${c.CRITICAL}C · ${c.HIGH}H · ${c.MEDIUM}M · ${c.LOW}L — penalty −${risk.penalty}`;

  $("#kpiCritical").textContent = c.CRITICAL;
  $("#kpiHigh").textContent = c.HIGH;
  $("#kpiMedLow").textContent = c.MEDIUM + c.LOW;
  $("#kpiMedLowNote").textContent = `${c.MEDIUM} medium · ${c.LOW} low`;

  $("#kpiSessions").textContent = st.total;
  $("#kpiSessionsNote").textContent = `${st.tls} encrypted · ${st.plaintext} plaintext`;
  $("#kpiSecure").textContent = st.secure;
  $("#kpiSuspicious").textContent = st.suspicious;
  const mlOut = (r.sessions || []).filter(x => x.anomaly_ml && x.anomaly_ml.available && x.anomaly_ml.note === "outlier");
  const mlNote = $("#kpiSuspiciousNote");
  if (mlNote) mlNote.innerHTML = mlOut.length
    ? `anomaly ≥ 70 · <span style="color:var(--cyan)">${mlOut.length} ML outlier${mlOut.length > 1 ? "s" : ""}</span>`
    : "anomaly score ≥ 70";
  $("#kpiSource").textContent = r.meta.file_label || r.scenario_id;
  $("#kpiSourceNote").textContent = `${r.meta.name} · ${r.meta.capture_window || ""}`;

  drawBars("chartProto", r.protocols.map(p => [p.name + "  (" + p.sessions + " sess, " + p.confidence + "% conf)", p.sessions]));
  drawBars("chartTls", Object.entries(r.tls_versions).map(([v, n]) => [v, n]).sort((a, b) => b[1] - a[1]));
  drawBars("chartCipher",
    [["STRONG", r.cipher_security.STRONG], ["LEGACY", r.cipher_security.LEGACY],
     ["WEAK", r.cipher_security.WEAK], ["NONE", r.cipher_security.NONE]],
    { STRONG: "#30a46c", LEGACY: "#f5d90a", WEAK: "#e5484d", NONE: "#5a6b85" });

  // recent findings (top 6 by severity) — rows jump to the Findings Center
  const tf = $("#dashFindings");
  tf.innerHTML = r.findings.slice(0, 6).map(f => `
    <tr class="clickable" data-fkey="${esc(f.rule_id + "|" + f.title)}" title="Open in Findings Center">
      <td><span class="chip ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
      <td><b>${esc(f.rule_id)}</b> ${esc(f.title)}<div class="dim" style="font-size:11px">${esc(f.summary || "")}</div></td>
      <td class="mono">${esc(f.sessions.slice(0, 3).join(", "))}${f.sessions.length > 3 ? " +" + (f.sessions.length - 3) : ""}</td>
      <td><span class="chip outline">${S.resolved.has(f.rule_id + "|" + f.title) ? "RESOLVED" : "OPEN"}</span></td>
    </tr>`).join("") || `<tr><td colspan="4" class="empty">No findings — posture is clean.</td></tr>`;
  tf.querySelectorAll("tr.clickable").forEach(tr => tr.addEventListener("click", () => {
    S.findFilter = "ALL";
    $$("#findFilters button").forEach(x => x.classList.toggle("active", x.dataset.f === "ALL"));
    renderFindings();
    $$("nav button").find(b => b.dataset.view === "findings").click();
    toggleFindingDetail(tr.dataset.fkey, true);
  }));

  drawTrend("chartTrend", r);
}

/* ------------------------------------------------------------------ canvas charts */
function prepCanvas(id) {
  const c = document.getElementById(id);
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth || 300, h = c.clientHeight || 190;
  c.width = w * dpr; c.height = h * dpr;
  const ctx = c.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, w, h };
}

/* theme-aware chart palette (canvas cannot read CSS variables) */
function themeChartColors() {
  if (currentTheme() === "light") {
    return { track: "#e3e8f0", grid: "#d5dce6", label: "#5b6b7f", dim: "#8b98a8", panel: "#eef1f6", bar: "#0e7490" };
  }
  return { track: "#1e2a45", grid: "#1e2a45", label: "#8296b3", dim: "#5a6b85", panel: "#0e1626", bar: "#22d3ee" };
}

function drawGauge(id, score) {
  const { ctx, w, h } = prepCanvas(id);
  const cx = w / 2, cy = h / 2, rad = Math.min(w, h) / 2 - 12;
  const col = score >= 90 ? "#30a46c" : score >= 75 ? "#46c46c" : score >= 50 ? "#f5d90a" : score >= 25 ? "#f76b15" : "#e5484d";
  const C = themeChartColors();
  ctx.lineWidth = 13; ctx.lineCap = "round";
  ctx.shadowColor = col + "55"; ctx.shadowBlur = 10;
  // background arc 135°..405°
  ctx.strokeStyle = C.track;
  ctx.beginPath(); ctx.arc(cx, cy, rad, Math.PI * 0.75, Math.PI * 2.25); ctx.stroke();
  // value arc
  ctx.strokeStyle = col;
  ctx.beginPath(); ctx.arc(cx, cy, rad, Math.PI * 0.75, Math.PI * 0.75 + Math.PI * 1.5 * (score / 100)); ctx.stroke();
  ctx.shadowBlur = 0;
}

/* count-up animation for the main posture gauge (respecting reduced motion) */
const REDUCED = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
function animateGauge(id, scoreElId, score) {
  const el = $("#" + scoreElId);
  if (REDUCED) { drawGauge(id, score); el.textContent = score; return; }
  const t0 = performance.now(), dur = 700, from = 0;
  const tick = (t) => {
    const p = Math.min(1, (t - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);
    const v = Math.round(from + (score - from) * eased);
    drawGauge(id, v);
    el.textContent = v;
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/* live posture chip in the top bar */
function updateTopChip(score, band) {
  const chip = $("#topStatus");
  if (!chip) return;
  chip.style.display = "";
  $("#topStatusScore").textContent = score + "/100";
  $("#topStatusBand").textContent = band;
  chip.className = "status-chip " +
    (band === "SECURE" || band === "LOW RISK" ? "band-secure"
      : band === "MODERATE RISK" ? "band-warn" : "band-risk");
}

function drawBars(id, entries, colorMap) {
  const { ctx, w, h } = prepCanvas(id);
  const C = themeChartColors();
  const total = entries.reduce((a, [_, n]) => a + n, 0);
  const max = Math.max(1, ...entries.map(e => e[1]));
  const bh = 20, gap = 8;
  let y = 8;
  ctx.font = "11px Consolas, monospace";
  for (const [label, n] of entries) {
    const frac = n / max;
    const pct = total ? Math.round(100 * n / total) : 0;
    const color = colorMap ? colorMap[label] : C.bar;
    ctx.fillStyle = C.label;
    ctx.fillText(label, 0, y + 12);
    // bar
    ctx.fillStyle = C.panel;
    roundRect(ctx, 0, y + 16, w - 34, 7, 3.5); ctx.fill();
    ctx.fillStyle = color;
    if (n > 0) { roundRect(ctx, 0, y + 16, Math.max(4, (w - 34) * frac), 7, 3.5); ctx.fill(); }
    ctx.fillStyle = n > 0 ? color : C.dim;
    ctx.textAlign = "right";
    ctx.fillText(String(n), w - 2, y + 12);
    ctx.textAlign = "left";
    y += bh + gap;
  }
}

function roundRect(ctx, x, y, w, h, r) {
  ctx.beginPath();
  ctx.moveTo(x + r, y);
  ctx.arcTo(x + w, y, x + w, y + h, r);
  ctx.arcTo(x + w, y + h, x, y + h, r);
  ctx.arcTo(x, y + h, x, y, r);
  ctx.arcTo(x, y, x + w, y, r);
  ctx.closePath();
}

function drawTrend(id, result) {
  /* Session Risk Profile — each session's risk score, worst first (real data). */
  const { ctx, w, h } = prepCanvas(id);
  const sessions = [...result.sessions].sort((a, b) => a.risk.score - b.risk.score);
  const n = sessions.length || 1;
  const padL = 24, padB = 26, padT = 10;
  const plotW = w - padL - 6, plotH = h - padB - padT;
  const bw = Math.max(3, Math.min(18, plotW / n - 3));
  const px = (i) => padL + (plotW / n) * i + (plotW / n - bw) / 2;
  const py = (v) => padT + plotH * (1 - v / 100);
  // grid
  const C = themeChartColors();
  ctx.strokeStyle = C.grid; ctx.fillStyle = C.dim; ctx.font = "10px Consolas";
  [0, 50, 100].forEach(v => {
    ctx.beginPath(); ctx.moveTo(padL - 4, py(v)); ctx.lineTo(w - 4, py(v)); ctx.stroke();
    ctx.fillText(String(v), 2, py(v) + 3);
  });
  // bars colored by band
  sessions.forEach((s, i) => {
    ctx.fillStyle = RISK_COLOR[s.risk.band] || C.bar;
    const y = py(s.risk.score);
    ctx.fillRect(px(i), y, bw, padT + plotH - y);
  });
  // caption: worst session callout
  const worst = sessions[0];
  ctx.fillStyle = C.label;
  ctx.fillText(worst ? `worst: ${worst.id} · ${worst.risk.score}/100` : "no sessions", padL, h - 8);
  ctx.textAlign = "right";
  ctx.fillText(`${n} sessions`, w - 6, h - 8);
  ctx.textAlign = "left";
}

/* ------------------------------------------------------------------ sessions */
function sessStatus(s) {
  return s.risk.band === "SECURE" || s.risk.band === "LOW RISK" ? "SECURE" : "AT RISK";
}

function renderSessions() {
  const r = S.result;
  if (!r) return;
  $("#sessEmpty").style.display = "none";
  $("#sessContent").style.display = "";
  const tb = $("#sessRows");
  const rows = r.sessions.filter(s => passFilter(s, S.sessFilter));
  tb.innerHTML = rows.map(s => `
    <tr class="clickable" data-sid="${esc(s.id)}">
      <td class="mono">${esc(s.id)}</td>
      <td>${esc(s.protocol)}</td>
      <td class="mono dim">${esc(s.src)}</td>
      <td class="mono">${esc(s.dst)}</td>
      <td>${esc(s.tls)}</td>
      <td class="mono" style="${weakVersion(s) ? "color:var(--sev-high);font-weight:700" : ""}">${esc(s.tls_version || "—")}</td>
      <td class="mono" style="${weakCipher(s) ? "color:var(--sev-high)" : ""}">${esc(s.cipher || "—")}</td>
      <td>${certChip(s)}</td>
      <td><b style="color:${RISK_COLOR[s.risk.band] || "var(--muted)"}">${s.risk.score}</b></td>
      <td class="status ${sessStatus(s) === "SECURE" ? "secure" : "atrisk"}">${sessStatus(s)}</td>
    </tr>`).join("") || `<tr><td colspan="10" class="empty">No sessions match this filter.</td></tr>`;
  tb.querySelectorAll("tr.clickable").forEach(tr => {
    tr.setAttribute("tabindex", "0");
    tr.setAttribute("role", "button");
    tr.setAttribute("aria-label", "Inspect session " + tr.dataset.sid);
    tr.addEventListener("click", () => openDrawer(tr.dataset.sid));
    tr.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openDrawer(tr.dataset.sid); }
    });
  });
}

function weakVersion(s) { return s.tls_version && /SSL|TLS 1\.0|TLS 1\.1/.test(s.tls_version); }
function weakCipher(s) { return s.cipher && /RC4|3DES|DES|NULL|EXP|MD5/.test(s.cipher.toUpperCase()); }

function certChip(s) {
  if (!s.certificate) return `<span class="chip outline">NONE</span>`;
  const st = s.certificate.status;
  const cls = st === "VALID" ? "low" : st === "EXPIRED" ? "high" : "critical";
  return `<span class="chip ${cls}">${esc(st)}</span>`;
}

function passFilter(s, f) {
  if (f === "ALL") return true;
  if (["SECURE", "AT RISK"].includes(f)) return sessStatus(s) === f;
  return s.protocol === f;
}

function bindFilters() {
  $("#sessFilters").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    $$("#sessFilters button").forEach(x => x.classList.toggle("active", x === b));
    S.sessFilter = b.dataset.f;
    renderSessions();
  });
  $("#findFilters").addEventListener("click", (e) => {
    const b = e.target.closest("button"); if (!b) return;
    $$("#findFilters button").forEach(x => x.classList.toggle("active", x === b));
    S.findFilter = b.dataset.f;
    renderFindings();
  });
}

/* ------------------------------------------------------------------ session drawer */
function bindDrawer() {
  $("#drawerBack").addEventListener("click", (e) => {
    if (e.target === $("#drawerBack")) closeDrawer();
  });
  document.addEventListener("keydown", (e) => e.key === "Escape" && closeDrawer());
}

function closeDrawer() { $("#drawerBack").classList.remove("open"); }

/* ------------------------------------------------------------------ dashboard */
function tlsVerName(v) {
  if (!Array.isArray(v)) return String(v || "?");
  return ({ "3,4": "TLS 1.3", "3,3": "TLS 1.2", "3,2": "TLS 1.1", "3,1": "TLS 1.0", "3,0": "SSLv3" })[v[0] + "," + v[1]] || ("0x" + v[0] + v[1]);
}

/* cleartext protocol transcript from the pre-TLS remainder bytes */
function hexTranscript(hex, dir, lines) {
  if (!hex) return;
  let txt = "";
  for (let i = 0; i < hex.length; i += 2) {
    const c = parseInt(hex.substr(i, 2), 16);
    txt += String.fromCharCode(c);
  }
  for (const ln of txt.split(/\r?\n/)) {
    const t = ln.replace(/[^\x20-\x7e]/g, "").trim();
    if (t.length >= 4 && lines.length < 14) lines.push([dir, "plain", t]);
  }
}

/* real parsed TLS records from an uploaded capture → drawer stream viewer */
function streamViewerHtml(s) {
  const ts = s.tls_stream;
  if (!ts) return "";
  const lines = [];
  if (ts.plaintext_phase) {
    // chronological cleartext transcript (STARTTLS negotiation visible byte-for-byte)
    hexTranscript(ts.remainders && ts.remainders.client, "C → S", lines);
    hexTranscript(ts.remainders && ts.remainders.server, "S → C", lines);
  }
  if (ts.client_cmd) lines.push(["C → S", "plain", "STARTTLS requested by client"]);
  const recCount = (ts.client || []).length + (ts.server || []).length;
  for (const e of [...(ts.client || [])].map(e => ["C → S", e])
      .concat([...(ts.server || [])].map(e => ["S → C", e]))) {
    const [dir, ev] = e;
    if (ev.kind === "handshake") {
      for (const m of (ev.messages || [])) {
        if (m.type === 1) lines.push([dir, "handshake", `ClientHello — ${tlsVerName(m.version)} · ${(m.ciphers || []).length} ciphers offered` + (m.sni ? ` · SNI "${m.sni}"` : "")]);
        else if (m.type === 2) lines.push([dir, "handshake", `ServerHello — ${tlsVerName(m.version)} · cipher 0x${m.cipher || "—"}`]);
        else if (m.type === 11) lines.push([dir, "handshake", `Certificate — ${(m.certs || []).length} DER entr${((m.certs || []).length === 1) ? "y" : "ies"} received`]);
        else if (m.type === 12) lines.push([dir, "handshake", "ServerKeyExchange"]);
        else if (m.type === 14) lines.push([dir, "handshake", "ServerHelloDone"]);
        else if (m.type === 16) lines.push([dir, "handshake", "ClientKeyExchange"]);
        else if (!m.parse_error) lines.push([dir, "handshake", `handshake message (type ${m.type})`]);
      }
    } else if (ev.kind === "alert") lines.push([dir, "alert", `TLS alert — level ${ev.level}, description ${ev.description}`]);
    else if (ev.kind === "ccs") lines.push([dir, "ccs", "ChangeCipherSpec — switching to encryption"]);
    else if (ev.kind === "appdata") lines.push([dir, "appdata", "encrypted application data"]);
  }
  if (!lines.length) return "";
  const subtitle = recCount
    ? `${recCount} TLS record${recCount > 1 ? "s" : ""} parsed`
    : "cleartext session — no TLS records";
  return `
    <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:16px 0 4px">Captured TLS Stream
      <span class="chip outline" style="float:right;text-transform:none;letter-spacing:0">parsed from capture · ${subtitle}</span></h3>
    <div class="stream-box">${lines.map(([d, k, t]) => `
      <div class="stream-line"><span class="stream-dir">${esc(d)}</span><span class="stream-kind ${k}">${esc(k)}</span><span>${esc(t)}</span></div>`).join("")}</div>`;
}

/* reconstructed handshake stream for evaluation scenarios (dataset doesn't carry
   real records, so the timeline is rebuilt from the session's TLS facts; the
   chip says "reconstructed" to stay honest about what's real evidence) */
function datasetStreamHtml(s) {
  if (s.tls_stream) return "";   // uploaded capture — real parsed records already rendered
  const starttls = s.starttls_events;   // reserved: per-session STARTTLS facts if added to datasets
  const isMailPort = [25, 587, 465, 110, 143, 993, 995].includes(s.dst_port);
  const hasTls = s.tls && s.tls !== "PLAINTEXT";
  // plaintext SMTP session = failed STARTTLS upgrade (strip facts live in the dataset anomaly notes)
  const canStarttls = [25, 587].includes(s.dst_port);
  if (!isMailPort || (!hasTls && !(starttls || canStarttls))) return "";
  const lines = [];
  const ch = s.tls_version || "TLS 1.2";
  const chStr = `ClientHello — ${ch} · STARTTLS advertised`;
  const shStr = `ServerHello — ${ch} · cipher ${s.cipher || "—"}`;
  if (hasTls && s.tls === "STARTTLS") {
    lines.push(["C → S", "plain", "STARTTLS requested by client"]);
    lines.push(["S → C", "plain", "220 Ready to start TLS"]);
  }
  lines.push(["C → S", "handshake", chStr]);
  if (hasTls) {
    lines.push(["S → C", "handshake", shStr]);
    if (s.cert) lines.push(["S → C", "handshake", `Certificate — ${s.certificate ? s.certificate.subject : ""}`]);
    lines.push(["C → S", "handshake", `KeyExchange — ${s.key_exchange || "—"} · forward secrecy: ${s.forward_secrecy ? "YES" : "NO"}`]);
    lines.push(["S → C", "ccs", "ChangeCipherSpec — switching to encryption"]);
    lines.push(["C → S", "ccs", "ChangeCipherSpec — switching to encryption"]);
    lines.push(["S → C", "appdata", "encrypted application data"]);
    lines.push(["C → S", "appdata", "encrypted application data"]);
  } else {
    lines.push(["C → S", "plain", "STARTTLS requested by client"]);
    lines.push(["S → C", "alert", "no TLS response — plaintext continued (STARTTLS stripped)"]);
  }
  const subtitle = hasTls ? "reconstructed from session facts · not from the capture bytes" : "reconstructed timeline of the failed upgrade";
  return `
    <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:16px 0 4px">TLS Stream (Reconstructed)
      <span class="chip outline" style="float:right;text-transform:none;letter-spacing:0">reconstructed · ${subtitle}</span></h3>
    <div class="stream-box">${lines.map(([d, k, t]) => `
      <div class="stream-line"><span class="stream-dir">${esc(d)}</span><span class="stream-kind ${k}">${esc(k)}</span><span>${esc(t)}</span></div>`).join("")}</div>`;
}

function openDrawer(sid) {
  const s = S.result.sessions.find(x => x.id === sid);
  if (!s) return;
  S.drawerSession = s;
  if (!s._inspected) {           // record the first inspection per session per analysis
    s._inspected = true;
    auditClient("session_inspect",
      `${s.id} (${s.protocol}) — TLS ${s.tls_version || "none"}, ${s.cipher || "no cipher"}, anomaly ${s.anomaly.score}/100`);
  }
  const weakV = weakVersion(s), weakC = weakCipher(s);
  const cert = s.certificate;
  const anomaly = s.anomaly;
  const ai = s.ai;

  const hsSteps = [
    ["TCP Established", `${s.src}:${s.src_port} → ${s.dst}:${s.dst_port}`, false],
    [s.tls === "PLAINTEXT" ? "STARTTLS Attempt" : "STARTTLS Negotiated",
     s.tls === "PLAINTEXT" ? "encryption transition FAILED — plaintext continued" : "client advertised, server accepted", s.tls === "PLAINTEXT"],
    ["ClientHello / ServerHello", `TLS ${s.tls_version || "—"} · cipher ${s.cipher || "—"}`, weakV || weakC],
    ["Certificate Exchange", cert ? `${cert.subject} — ${cert.status}` : "no certificate", cert && cert.status !== "VALID"],
    ["Key Exchange", `${s.key_exchange || "—"} · forward secrecy: ${s.forward_secrecy ? "YES" : "NO"}`, s.forward_secrecy === false],
    ["Encrypted Session", s.tls === "PLAINTEXT" ? "NEVER REACHED — data sent in cleartext" : "application data flowing", s.tls === "PLAINTEXT"],
  ];

  $("#drawer").innerHTML = `
    <button class="close" title="Close (Esc)">×</button>
    <h2>${esc(s.id)} <span class="chip outline">${esc(s.protocol)}</span>
      <span class="status ${sessStatus(s) === "SECURE" ? "secure" : "atrisk"}" style="font-size:13px;margin-left:6px">${sessStatus(s)}</span></h2>
    <div class="subtle" style="margin-bottom:14px">${esc(s.src)}:${s.src_port} → ${esc(s.dst)}:${s.dst_port} · ${s.packets} packets · ${(s.bytes / 1024).toFixed(1)} KB · ${s.duration_s}s</div>

    <div class="grid g2" style="gap:12px">
      <div>
        <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">TLS Negotiation</h3>
        <dl class="kv">
          <dt>Transport security</dt><dd class="${s.tls === "PLAINTEXT" ? "weak" : "good"}">${esc(s.tls)}</dd>
          <dt>TLS version</dt><dd class="${weakV ? "weak" : ""}">${esc(s.tls_version || "—")}</dd>
          <dt>Cipher suite</dt><dd class="${weakC ? "weak" : ""}">${esc(s.cipher || "—")}</dd>
          <dt>Key exchange</dt><dd>${esc(s.key_exchange || "—")}</dd>
          <dt>Forward secrecy</dt><dd class="${s.forward_secrecy ? "good" : "weak"}">${s.forward_secrecy ? "Yes" : "No"}</dd>
        </dl>
      </div>
      <div>
        <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Certificate</h3>
        ${cert ? `
        <dl class="kv">
          <dt>Subject</dt><dd>${esc(cert.subject)}</dd>
          <dt>Issuer</dt><dd>${esc(cert.issuer)}</dd>
          <dt>Valid from</dt><dd>${esc(cert.valid_from)}</dd>
          <dt>Valid until</dt><dd class="${cert.status !== "VALID" ? "weak" : ""}">${esc(cert.valid_until)} ${cert.days_expired ? `(expired ${cert.days_expired}d ago)` : ""}</dd>
          <dt>Public key</dt><dd>${esc(cert.key_alg)} ${cert.key_len}</dd>
          <dt>Signature</dt><dd>${esc(cert.sig_alg)}</dd>
          <dt>Status</dt><dd class="${cert.status === "VALID" ? "good" : "weak"}"><b>${esc(cert.status)}</b></dd>
        </dl>` : `<div class="subtle">No certificate presented (plaintext session).</div>`}
      </div>
    </div>

    <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:16px 0 4px">TLS Handshake Timeline</h3>
    <div class="hs">
      ${hsSteps.map(([t, d, bad]) => `
        <div class="hs-step">
          <div class="hs-rail"><div class="hs-dot ${bad ? "bad" : ""}"></div><div class="hs-line"></div></div>
          <div class="hs-body"><b>${esc(t)}</b><div class="d ${bad ? "bad" : ""}">${esc(d)}</div></div>
        </div>`).join("")}
    </div>
    ${streamViewerHtml(s)}
    ${datasetStreamHtml(s)}

    <div class="grid g2" style="gap:12px">
      <div>
        <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Anomaly Detection</h3>
        <div style="display:flex;justify-content:space-between;font-size:12px"><span>Anomaly score</span><b style="color:${anomaly.score >= 70 ? "var(--sev-critical)" : anomaly.score >= 40 ? "var(--amber)" : "var(--green)"}">${anomaly.score}/100 · ${esc(anomaly.level)}</b></div>
        <div class="agauge"><div class="fill" style="width:${anomaly.score}%;background:${anomaly.score >= 70 ? "var(--sev-critical)" : anomaly.score >= 40 ? "var(--amber)" : "var(--green)"}"></div></div>
        <div style="font-size:11.5px;color:var(--muted)">Confidence: ${anomaly.confidence}%</div>
        ${s.anomaly_ml && s.anomaly_ml.available ? `<div class="subtle" style="margin-top:4px">ML assist — unsupervised IsolationForest: <b>${esc(s.anomaly_ml.note || "—")}</b> (outlier score ${s.anomaly_ml.score}/100)</div>` : ""}
        ${anomaly.detected.length ? `<ul class="steps">${anomaly.detected.map(d => `<li>${esc(d)}</li>`).join("")}</ul>` : `<div class="subtle" style="margin-top:4px">No anomalies detected.</div>`}
      </div>
      <div>
        <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">AI-Assisted Assessment</h3>
        <div class="kv" style="grid-template-columns:110px 1fr">
          <dt>Risk class</dt><dd><b style="color:${ai.risk_class === "CRITICAL" || ai.risk_class === "HIGH" ? "var(--sev-critical)" : ai.risk_class === "MODERATE" ? "var(--amber)" : "var(--green)"}">${esc(ai.risk_class)}</b></dd>
          <dt>Confidence</dt><dd>${ai.confidence}%</dd>
          <dt>Priority</dt><dd><span class="chip ${ai.priority === "P1" ? "critical" : "outline"}">${esc(ai.priority)}</span></dd>
        </dl>
        <div class="subtle" style="margin-top:6px">“${esc(ai.reason)}”</div>
        <div class="subtle" style="margin-top:4px">${esc(ai.priority_reason)}</div>
      </div>
    </div>

    <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:16px 0 6px">Detected Weaknesses</h3>
    ${s.findings.length ? `
      <table class="tbl"><tbody>
        ${s.findings.map(x => `<tr><td class="mono" style="width:110px">${esc(x.split(":")[0])}</td><td>${esc(x.split(": ").slice(1).join(": "))}</td></tr>`).join("")}
      </tbody></table>
      <div style="margin-top:8px">Session risk <b style="color:${RISK_COLOR[s.risk.band]}">${s.risk.score}/100 · ${esc(s.risk.band)}</b>
      <span class="subtle">(penalty −${s.risk.penalty})</span></div>`
      : `<div class="subtle">No cryptographic weaknesses detected in this session.</div>`}

    <h3 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin:16px 0 6px">Recommended Remediation</h3>
    ${s.findings.length ? `
      <div class="finding-detail">
        ${remediationForSession(s)}
      </div>`
      : `<div class="subtle">Nothing to remediate — session configuration follows RFC 8314 guidance.</div>`}        <div class="ai-note">${esc(ai.note)}</div>
  `;
  $("#drawer .close").addEventListener("click", closeDrawer);
  $("#drawerBack").classList.add("open");
}

function remediationForSession(s) {
  // derive concrete steps from session features (deterministic)
  const steps = [];
  if (s.tls === "PLAINTEXT") steps.push("Enforce STARTTLS/implicit TLS on this mail path — reject plaintext fallback.");
  if (weakVersion(s)) steps.push(`Disable ${(s.tls_version || "").trim()} and require TLS 1.2+ (prefer TLS 1.3) per RFC 8314.`);
  if (weakCipher(s)) steps.push("Remove weak cipher suites (3DES/RC4/legacy CBC); configure AEAD suites (AES-GCM / ChaCha20).");
  if (s.certificate && s.certificate.status !== "VALID") steps.push(`Renew the certificate for ${s.certificate.subject} before its replacement window closes.`);
  if (s.forward_secrecy === false) steps.push("Enable ECDHE key exchange to provide forward secrecy.");
  if (!steps.length) steps.push("No action required — configuration aligns with RFC 8314 / NIST SP 800-52.");
  return `<ol class="steps">${steps.map(x => `<li>${esc(x)}</li>`).join("")}</ol>`;
}

/* ------------------------------------------------------------------ findings */
function findRiskBadge(f) {
  return `<b style="color:${SEV_COLOR[f.severity]}">−${{ CRITICAL: 30, HIGH: 20, MEDIUM: 10, LOW: 5 }[f.severity]}</b>`;
}

function renderFindings() {
  const r = S.result;
  if (!r) return;
  $("#findEmpty").style.display = "none";
  $("#findContent").style.display = "";
  const statusOf = (f) => S.resolved.has(f.rule_id + "|" + f.title) ? "RESOLVED" : "OPEN";
  const rows = r.findings.filter(f => {
    const st = statusOf(f);
    if (S.findFilter === "ALL") return true;
    if (S.findFilter === "OPEN" || S.findFilter === "RESOLVED") return st === S.findFilter;
    return f.severity === S.findFilter;
  });
  $("#findRows").innerHTML = rows.map(f => `
    <tr class="clickable sev-${f.severity.toLowerCase()}" data-key="${esc(f.rule_id + "|" + f.title)}">
      <td><span class="chip ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
      <td><b class="mono">${esc(f.rule_id)}</b> ${esc(f.title)}<div class="dim" style="font-size:11px">${esc(f.summary || "")}</div></td>
      <td class="mono dim">${esc(f.sessions.join(", "))}</td>
      <td class="dim" style="max-width:260px;font-size:11.5px">${esc((f.evidence[0] || "").slice(0, 90))}${(f.evidence[0] || "").length > 90 ? "…" : ""}</td>
      <td>${findRiskBadge(f)}</td>
      <td>${statusOf(f) === "RESOLVED" ? `<span class="resolved-tag">RESOLVED</span>` : `<span class="chip outline">OPEN</span>`}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="empty">No findings match this filter.</td></tr>`;

  $("#findRows").querySelectorAll("tr.clickable").forEach(tr =>
    tr.addEventListener("click", () => toggleFindingDetail(tr.dataset.key)));
  // keep resolved details collapsed
}

function toggleFindingDetail(key, forceOpen = false) {
  const existing = document.getElementById("fd-" + CSS.escape(key));
  if (existing) { if (!forceOpen) existing.remove(); return; }
  const f = S.result.findings.find(x => (x.rule_id + "|" + x.title) === key);
  if (!f) return;
  const tr = document.createElement("tr");
  tr.id = "fd-" + CSS.escape(key);
  tr.innerHTML = `<td colspan="6" style="padding:0">
    <div class="finding-detail">
      <b>${esc(f.rule_id)} — ${esc(f.title)}</b>
      <span class="chip ${f.severity.toLowerCase()}" style="margin-left:8px">${esc(f.severity)}</span>
      <h4>Evidence</h4>
      ${f.evidence.map(e => `<div class="evi">${esc(e)}</div>`).join("")}
      <h4>Impact</h4><div>${esc(f.impact)}</div>
      <h4>Recommendation</h4><div>${esc(f.recommendation)}</div>
      <h4>Affected Sessions (${f.sessions.length})</h4>
      <div class="mono" style="font-size:11.5px;color:var(--muted)">${esc(f.sessions.join(", "))}</div>
    </div></td>`;
  const anchor = $(`#findRows tr[data-key="${CSS.escape(key)}"]`);
  anchor.after(tr);
}

/* ------------------------------------------------------------------ remediation */
function renderRemediation() {
  const r = S.result;
  if (!r) return;
  $("#remEmpty").style.display = "none";
  $("#remContent").style.display = "";
  const list = $("#remList");
  list.innerHTML = "";
  for (const f of r.findings) {
    const key = f.rule_id + "|" + f.title;
    const resolved = S.resolved.has(key);
    const card = document.createElement("div");
    card.className = "card";
    card.style.marginBottom = "10px";
    card.innerHTML = `
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px">
        <div>
          <span class="chip ${f.severity.toLowerCase()}">${esc(f.severity)}</span>
          <b class="mono" style="margin-left:6px">${esc(f.rule_id)}</b> <b>${esc(f.title)}</b>
          <span class="subtle"> — affects ${f.affected_count} session(s)</span>
        </div>
        <div>${resolved
          ? `<span class="resolved-tag">✓ RESOLVED</span>`
          : `<button class="btn small" data-res="${esc(key)}">Mark Resolved</button>`}</div>
      </div>
      <ol class="steps">${remSteps(f).map(x => `<li>${esc(x)}</li>`).join("")}</ol>`;
    list.appendChild(card);
  }
  list.querySelectorAll("[data-res]").forEach(b =>
    b.addEventListener("click", () => {
      S.resolved.add(b.dataset.res);
      renderRemediation();
      renderFindings();
    }));
  renderWhatIf();
}

function remSteps(f) {
  const byRule = {
    "TLS-001": ["Disable SSLv3, TLS 1.0 and TLS 1.1 on all mail endpoints.", "Require TLS 1.2, prefer TLS 1.3 (RFC 8314 §8).", "Review mail-server cipher configuration.", "Retest STARTTLS negotiation after the change."],
    "CIPH-001": ["Remove 3DES / RC4 / NULL / export cipher suites.", "Configure AEAD suites only (AES-GCM, ChaCha20-Poly1305).", "Enable TLS 1.3 suites where supported.", "Retest the handshake from an external vantage point."],
    "CERT-001": ["Renew the affected certificate immediately.", "Deploy ≥2048-bit RSA or ≥256-bit EC keys with SHA-256 signatures.", "Automate renewal and monitor expiry (≤30-day alerting).", "Verify the new chain is served before decommissioning the old one."],
    "SESS-001": ["Enforce TLS on all mail ports (25/465/587/993/995).", "Deploy MTA-STS and DANE to block STARTTLS downgrade.", "Reject cleartext fallback for partner mail flows.", "Re-scan the path to confirm encryption."],
    "SESS-002": ["Enable ECDHE key exchange on all endpoints.", "Disable static RSA key-exchange suites.", "Prefer TLS 1.3 (mandatory forward secrecy).", "Retest and confirm FS-capable negotiation."],
  };
  return byRule[f.rule_id] || [f.recommendation];
}

function renderWhatIf() {
  const r = S.result;
  const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const open = r.findings.filter(f => !S.resolved.has(f.rule_id + "|" + f.title));
  // real penalty math: projected posture = 100 − sum of penalties still open
  const openPenalty = open.reduce((a, f) => a + (SEV_PENALTY[f.severity] || 0), 0);
  const projected = Math.max(0, Math.min(100, 100 - openPenalty));
  drawGauge("gaugeWhatIf", projected);
  $("#gaugeWhatIfScore").textContent = projected;
  const bandEl = $("#whatIfBand");
  const b = projected >= 90 ? "SECURE" : projected >= 75 ? "LOW RISK" : projected >= 50 ? "MODERATE RISK" : projected >= 25 ? "HIGH RISK" : "CRITICAL";
  bandEl.textContent = b + (open.length ? ` — ${open.length} finding(s) still open` : " — all findings resolved");
  bandEl.className = "status " + (b === "SECURE" || b === "LOW RISK" ? "secure" : b === "MODERATE RISK" ? "warn" : "atrisk");
  const next = [...open].sort((a, b2) => sevRank[a.severity] - sevRank[b2.severity])[0];
  $("#whatIfNote").textContent = next
    ? `Next action: ${next.rule_id} ${next.title} (${next.severity}, −${SEV_PENALTY[next.severity]} posture points).`
    : "Full remediation simulated. In production, re-capture traffic to confirm the improved posture.";
}

/* ------------------------------------------------------------------ reporting */
async function exportReport(kind) {
  if (!S.result) { $("#reportHint").textContent = "Run an analysis first."; return; }
  const url = kind === "json" ? "/api/report/json" : "/api/report/html";
  try {
    const res = await fetch(url);
    if (!res.ok) { const e = await res.json(); $("#reportHint").textContent = e.error || "Export failed."; return; }
    if (kind === "json") {
      const data = await res.json();
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
      triggerDownload(blob, `securemailscope_report_${S.result.scenario_id}.json`);
      $("#reportHint").textContent = "JSON report exported.";
    } else {
      const html = await res.text();
      const blob = new Blob([html], { type: "text/html" });
      triggerDownload(blob, `securemailscope_report_${S.result.scenario_id}.html`);
      const iframe = $("#repFrame");
      iframe.srcdoc = html;
      $$("nav button").find(b => b.dataset.view === "report").click();
      $("#repEmpty").style.display = "none";
      $("#repContent").style.display = "";
      $("#reportHint").textContent = "HTML report generated — preview below, file downloaded.";
    }
  } catch (e) {
    $("#reportHint").textContent = "Export failed: " + e.message;
  }
}

function triggerDownload(blob, filename) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

/* redraw charts crisply when the window is resized */
let _rzT;
window.addEventListener("resize", () => {
  clearTimeout(_rzT);
  _rzT = setTimeout(() => { if (S.result) renderDashboard(); }, 150);
});
