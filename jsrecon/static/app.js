const $ = (id) => document.getElementById(id);
let JOB = null, KATJOB = null, ENDPOINTS = [], CURRENT = null, editable = false;

const fmtSize = (n) =>
  n > 1e9 ? (n/1e9).toFixed(1)+" GB" : n > 1e6 ? (n/1e6).toFixed(1)+" MB" :
  n > 1e3 ? (n/1e3).toFixed(1)+" KB" : n+" B";
const escapeHtml = (s) => (s||"").replace(/[&<>"]/g, (c) =>
  ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));

// ------------------------------ burp analyze ------------------------------
async function startAnalyze() {
  const f = $("xmlFile").files[0];
  if (!f) { alert("выбери Burp XML файл"); return; }
  return startAnalyzeUpload(f);
}

async function startAnalyzeUpload(file) {
  $("analyzeBtn").disabled = true; activateTab("log");
  $("status").textContent = `загрузка ${file.name}…`;
  const fd = new FormData();
  fd.append("file", file);
  fd.append("include_inline", $("inlineChk").checked);
  fd.append("include_traffic", $("trafficChk").checked);
  fd.append("do_secrets", $("secretsChk").checked);
  fd.append("do_semgrep", $("semgrepChk").checked);
  fd.append("verify_secrets", $("verifyChk").checked);
  fd.append("sourcemaps", $("mapsChk").checked);
  fd.append("fetch_remote_maps", $("fetchMapsChk").checked);
  fd.append("webpack", $("webpackChk").checked);
  fd.append("ignore_strings", $("ignoreChk").checked);
  const r = await fetch("/api/analyze-upload", { method:"POST", body: fd });
  if (!r.ok) { $("analyzeBtn").disabled=false;
    $("status").textContent = "ОШИБКА загрузки: " + (await r.text()); return; }
  const d = await r.json(); JOB = d.job; pollJob(JOB, () => $("analyzeBtn").disabled=false);
}

function renderLog(log, elapsed) {
  if (!log || !log.length) return;
  const lines = log.map((e, i) => {
    const next = log[i+1];
    const dur = (next ? next.t - e.t : elapsed - e.t);
    const cur = next ? "" : " ⏳";
    return `[+${e.t.toFixed(1)}s] ${(e.stage+cur).padEnd(13)} ${dur.toFixed(1)}s  ${e.message}`;
  });
  const box = $("logBox");
  box.textContent = lines.join("\n");
  box.scrollTop = box.scrollHeight;
}

async function pollJob(jid, onEnd) {
  localStorage.setItem("jsrecon_job", jid);   // survive a page reload
  const r = await fetch(`/api/jobs/${jid}`);
  if (!r.ok) { localStorage.removeItem("jsrecon_job"); onEnd && onEnd(); return; }
  const s = await r.json();
  $("status").textContent = `[${s.status}] ${s.stage} — ${s.message} · ${s.elapsed}s`;
  renderLog(s.log, s.elapsed);
  if (s.status === "done") { localStorage.removeItem("jsrecon_job"); onEnd && onEnd(); await refreshCombined(); activateTab("eps"); }
  else if (s.status === "error") { localStorage.removeItem("jsrecon_job"); onEnd && onEnd(); $("status").textContent = "ОШИБКА: " + s.error; }
  else setTimeout(() => pollJob(jid, onEnd), 900);
}

// After a reload, if a job was still running, re-attach to it so the log keeps
// streaming instead of vanishing.
function resumeJob() {
  const jid = localStorage.getItem("jsrecon_job");
  if (!jid) return;
  const reenable = () => {
    ["analyzeBtn","katBtn","arcBtn","dirBtn","urlsBtn"].forEach(b => { const el=$(b); if(el) el.disabled=false; });
    ["katStopBtn","arcStopBtn","dirStopBtn","urlsStopBtn"].forEach(b => { const el=$(b); if(el) el.hidden=true; });
  };
  activateTab("log");
  pollJob(jid, reenable);
}

// ------------------------------ katana ------------------------------
async function startKatana() {
  const domain = $("katDomain").value.trim();
  if (!domain) { alert("укажи домен"); return; }
  $("katBtn").disabled = true; $("katStopBtn").hidden = false; activateTab("log");
  const r = await fetch("/api/katana", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ domain, depth: parseInt($("katDepth").value)||2,
      headless:$("katHeadless").checked, use_session:$("katSession").checked,
      use_agent:$("katAgent").checked,
      do_secrets:$("katSecrets").checked, do_semgrep:$("katSemgrep").checked,
      verify_secrets:$("katVerify").checked, sourcemaps:$("katMaps").checked,
      webpack:$("katWebpack").checked }) });
  const d = await r.json(); KATJOB = d.job;
  pollJob(KATJOB, () => { $("katBtn").disabled=false; $("katStopBtn").hidden=true; });
}
async function stopKatana() {
  if (!KATJOB) return;
  await fetch(`/api/jobs/${KATJOB}/stop`, { method:"POST" });
  $("status").textContent = "katana остановлена";
}

// ------------------------------ archive (gau + wayback) ------------------------------
let ARCJOB = null;
async function startArchive() {
  const domain = $("arcDomain").value.trim();
  if (!domain) { alert("укажи домен"); return; }
  $("arcBtn").disabled = true; $("arcStopBtn").hidden = false; activateTab("log");
  const r = await fetch("/api/archive", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ domain, use_gau:$("arcGau").checked, use_wayback:$("arcWayback").checked,
      subs:$("arcSubs").checked, use_session:$("arcSession").checked,
      do_semgrep:$("arcSemgrep").checked, webpack:$("arcWebpack").checked,
      sourcemaps:$("arcMaps").checked }) });
  const d = await r.json(); ARCJOB = d.job;
  pollJob(ARCJOB, () => { $("arcBtn").disabled=false; $("arcStopBtn").hidden=true; });
}
// ------------------------------ scan local dir (resume SAST) ------------------------------
let DIRJOB = null;
async function startScanDir() {
  const path = $("dirScanPath").value.trim();
  if (!path) { alert("укажи путь к каталогу"); return; }
  $("dirBtn").disabled = true; $("dirStopBtn").hidden = false; activateTab("log");
  const r = await fetch("/api/scan-dir", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ path, do_secrets:$("dirSecrets").checked,
      do_semgrep:$("dirSemgrep").checked, verify_secrets:$("dirVerify").checked }) });
  if (!r.ok) { $("dirBtn").disabled=false; $("dirStopBtn").hidden=true;
    $("status").textContent = "ОШИБКА: " + (await r.text()); return; }
  const d = await r.json(); DIRJOB = d.job;
  pollJob(DIRJOB, () => { $("dirBtn").disabled=false; $("dirStopBtn").hidden=true; });
}
async function stopScanDir() {
  if (!DIRJOB) return;
  await fetch(`/api/jobs/${DIRJOB}/stop`, { method:"POST" });
  $("status").textContent = "скан каталога остановлен";
}

// ------------------------------ scan list of JS URLs from .txt ------------------------------
let URLSJOB = null, URLS_LIST = [];
function parseUrlsFile() {
  const f = $("urlsFile").files[0];
  if (!f) { URLS_LIST = []; $("urlsCount").textContent = ""; return; }
  const reader = new FileReader();
  reader.onload = () => {
    URLS_LIST = reader.result.split(/\r?\n/).map(s => s.trim())
      .filter(s => s && !s.startsWith("#"));
    $("urlsCount").textContent = `${URLS_LIST.length} URL`;
  };
  reader.readAsText(f);
}
async function startScanUrls() {
  if (!URLS_LIST.length) { alert("выбери .txt со списком URL"); return; }
  $("urlsBtn").disabled = true; $("urlsStopBtn").hidden = false; activateTab("log");
  const r = await fetch("/api/scan-urls", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ urls: URLS_LIST, use_session:$("urlsSession").checked,
      do_secrets:$("urlsSecrets").checked, do_semgrep:$("urlsSemgrep").checked,
      verify_secrets:$("urlsVerify").checked, webpack:$("urlsWebpack").checked,
      sourcemaps:$("urlsMaps").checked }) });
  if (!r.ok) { $("urlsBtn").disabled=false; $("urlsStopBtn").hidden=true;
    $("status").textContent = "ОШИБКА: " + (await r.text()); return; }
  const d = await r.json(); URLSJOB = d.job;
  pollJob(URLSJOB, () => { $("urlsBtn").disabled=false; $("urlsStopBtn").hidden=true; });
}
async function stopScanUrls() {
  if (!URLSJOB) return;
  await fetch(`/api/jobs/${URLSJOB}/stop`, { method:"POST" });
  $("status").textContent = "скан списка остановлен";
}

async function stopArchive() {
  if (!ARCJOB) return;
  await fetch(`/api/jobs/${ARCJOB}/stop`, { method:"POST" });
  $("status").textContent = "archive остановлен";
}

// ------------------------------ combined (project) ------------------------------
function currentFilter() { return $("filterInput").value.trim(); }
function excludeStatic() { return !$("staticChk").checked; }

async function refreshCombined() {
  await Promise.all([loadEndpoints(), loadFindings(), loadDomains()]);
  updateLinks();
}

async function loadDomains() {
  const r = await fetch("/api/combined/domains");
  if (!r.ok) return;
  const d = await r.json();
  $("domCount").textContent = d.count ? `(${d.count})` : "";
  const ul = $("domList"); ul.innerHTML = "";
  for (const row of (d.domains||[])) {
    const li = document.createElement("li");
    li.className = "domRow";
    const unknown = row.host === "?";
    const left = document.createElement("span");
    left.className = "domLeft";
    left.title = "фильтр по этому домену";
    left.innerHTML = `<b>${unknown ? '❓ неизвестный хост' : escapeHtml(row.host)}</b>` +
      `<span class="domCounts">api: ${row.api} · всего: ${row.total}</span>`;
    left.onclick = () => {
      $("filterInput").value = `domain=${row.host}`;
      loadEndpoints(); updateLinks(); activateTab("eps");
    };
    const btn = document.createElement("button");
    btn.className = "mini domRehost";
    btn.textContent = unknown ? "→ задать хост" : "→ заменить хост";
    btn.title = "перенести эти эндпоинты на другой домен";
    btn.onclick = async (e) => {
      e.stopPropagation();
      const to = prompt(`Перенести ${row.total} эндпоинтов с «${row.host}» на хост:`,
        unknown ? "api.yoomoney.ru" : row.host);
      if (!to) return;
      const r = await fetch("/api/combined/rehost", { method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ from_host: row.host, to_host: to }) });
      const res = await r.json();
      $("status").textContent = r.ok ? `перенесено ${res.moved} эндпоинтов на ${res.to_host}`
        : "ошибка: " + (res.detail||r.status);
      await refreshCombined();
    };
    li.appendChild(left);
    li.appendChild(btn);
    ul.appendChild(li);
  }
}

async function loadEndpoints() {
  const p = new URLSearchParams({ filter: currentFilter(), exclude_static: excludeStatic() });
  const r = await fetch(`/api/combined/endpoints?${p}`);
  if (!r.ok) { const e = await r.json(); $("status").textContent = "фильтр: "+(e.detail||r.status); return; }
  const d = await r.json();
  ENDPOINTS = d.endpoints;
  $("epCount").textContent = `(${d.count}/${d.total})`;
  renderList();
}

const CAT_CLASS = { api:"c-api", page:"c-page", static:"c-static" };
function renderList() {
  const ul = $("epList"); ul.innerHTML = "";
  for (const e of ENDPOINTS) {
    const li = document.createElement("li");
    li.dataset.idx = e.idx;
    const np = e.query_params.length + e.body_params.length;
    const tags = (e.tags||[]).map(t => `<span class="gftag">${t}</span>`).join("");
    const cnt = e.count > 1 ? `<span class="cnt">×${e.count}</span>` : "";
    li.innerHTML =
      `<span class="method m-${e.method}">${e.method}</span>` +
      `<span class="epPath"><span class="cat ${CAT_CLASS[e.category]||''}">${e.category}</span> ` +
      `${escapeHtml(e.path_template||e.path)}` + (np?`<span class="tag">${np}p</span>`:"") + cnt + tags +
      `<br><span class="epHost">${escapeHtml(e.host||"")}</span></span>`;
    li.onclick = () => selectEp(e.idx, li);
    ul.appendChild(li);
  }
}

async function selectEp(idx, li) {
  document.querySelectorAll("#epList li").forEach(x => x.classList.remove("active"));
  if (li) li.classList.add("active");
  const r = await fetch(`/api/combined/endpoint/${idx}`);
  const e = await r.json(); CURRENT = e; CURRENT.idx = idx;
  $("detailEmpty").hidden = true; $("detail").hidden = false;
  const ck = e.session_cookie
    ? `<span class="cookieOn">🍪 куки сессии (${e.session_cookie.split(";").length})</span>` : "";
  $("epMeta").innerHTML =
    `<b>${e.method}</b> ${escapeHtml(e.url)} ${ck}<br>` +
    `cat: <b>${e.category}</b> · query: ${e.query_params.join(", ")||"—"} · body: ${e.body_params.join(", ")||"—"}<br>` +
    `tags: ${(e.tags||[]).join(", ")||"—"} · тип: ${escapeHtml(e.detect_type||"—")} · @ ${escapeHtml((e.found_in||[])[0]||"—")}`;
  $("reqBox").value = e.raw_request; $("reqBox").readOnly = true;
  editable = false; $("editBtn").textContent = "✎ править";
  $("respBox").value = ""; $("respMeta").textContent = "";
}

async function loadFindings() {
  const r = await fetch("/api/combined/findings");
  const d = await r.json();
  $("findTab").hidden = !d.count;
  $("findCount").textContent = d.count ? `(${d.count})` : "";
  const ul = $("findList"); ul.innerHTML = "";
  for (const f of (d.findings||[])) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="sev sev-${f.severity}">${f.severity}</span>` +
      `<b>${escapeHtml(f.kind)}</b> <code>${escapeHtml(f.evidence)}</code>` +
      `<br><span class="epHost">${escapeHtml(f.location||"")}</span>`;
    ul.appendChild(li);
  }
}

function updateLinks() {
  const p = new URLSearchParams({ filter: currentFilter(), exclude_static: excludeStatic() });
  $("jsonLink").href = `/api/combined/report.json?${p}`;
  $("mdLink").href = `/api/combined/report.md?${p}`;
  $("swaggerLink").href = `/api/combined/openapi.json?${p}`;
}

// ------------------------------ project / proxy ------------------------------
async function saveProject() {
  const r = await fetch("/api/project/save", { method:"POST" });
  const d = await r.json().catch(()=>({}));
  $("status").textContent = r.ok ? `проект сохранён: ${d.endpoints} эндпоинтов, ${d.findings} находок`
                                 : "сохранение: " + (d.detail||r.status);
}
async function applyProxy() {
  const r = await fetch("/api/settings/proxy", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ server: $("proxyInput").value.trim() }) });
  const d = await r.json();
  $("status").textContent = d.proxy ? `прокси: ${d.proxy} (перезапусти сессию для применения к ней)` : "прокси выключен";
}
async function applyRate() {
  const v = parseFloat($("rateInput").value) || 0;
  const r = await fetch("/api/settings/rate", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ rps: v }) });
  const d = await r.json();
  $("status").textContent = d.rps > 0 ? `лимит: ${d.rps} запросов/сек` : "лимит запросов снят (без ограничений)";
}
async function loadRate() {
  const r = await fetch("/api/settings/rate"); if (!r.ok) return;
  const d = await r.json();
  if (d.rps) $("rateInput").value = d.rps;
}
async function loadMe() {
  const r = await fetch("/api/me"); if (!r.ok) return;
  const d = await r.json();
  $("userLabel").textContent = d.username;
  if (d.proxy) $("proxyInput").value = d.proxy;
  // auto-load saved project into the workspace, then show it
  if (d.project && d.project.exists) {
    await fetch("/api/project/load", { method:"POST" });
    $("status").textContent = `проект загружен (${d.project.endpoints} эндпоинтов)`;
  }
  await refreshCombined();
}

// ------------------------------ session ------------------------------
async function refreshSession() {
  const r = await fetch("/api/session/status"); if (!r.ok) return;
  const s = await r.json();
  const px = s.proxy || {};
  PROXY_ACTIVE = !!px.active;
  const pins = px.pins || [];
  let txt;
  if (px.active) {
    txt = `🕵 прокси: живые куки на ${px.hosts_with_cookies} хостах` +
          (s.agents ? ` · 🤖 агент активен (${s.agents})` : " · агента нет — открой страницу цели") +
          (pins.length ? ` · 📌 закреплено: ${pins.join(", ")}` : "") +
          (px.browser_running ? "" : " · направь браузер на прокси");
  } else txt = "прокси: нет";
  $("sessStatus").textContent = txt;
  $("sessStatus").className = "sessStatus " + (px.active || s.active ? "on" : "");

  // agent proxy status
  try {
    const apr = await fetch("/api/agent-proxy/status"); if (!apr.ok) return;
    const ap = await apr.json();
    const apEl = $("agentProxyStatus");
    if (ap.running) {
      apEl.textContent = `🔀 agent proxy :${ap.port}`;
      apEl.hidden = false;
    } else {
      apEl.hidden = true;
    }
  } catch(_) {}
}
$("sessStopBtn").onclick = async () => {
  await fetch("/api/session/proxy/stop",{method:"POST"});
  await fetch("/api/session/stop",{method:"POST"});
  refreshSession();
};
$("proxyBrowserBtn").onclick = async () => {
  $("sessStatus").textContent = "запуск прокси-браузера…";
  const r = await fetch("/api/session/proxy/start", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({}) });
  const d = await r.json();
  if (!r.ok) { $("sessStatus").textContent = "ошибка: "+(d.detail||r.status); return; }
  $("sessStatus").textContent = d.browser_launched
    ? `прокси-браузер запущен · открой цель и пройди ServicePipe`
    : `прокси на 127.0.0.1:${d.port} — направь свой браузер туда (${d.hint||""})`;
  refreshSession();
};

// ------------------------------ send ------------------------------
$("editBtn").onclick = () => {
  editable = !editable; $("reqBox").readOnly = !editable;
  $("editBtn").textContent = editable ? "✓ готово" : "✎ править";
};
function parseRawRequest(raw) {
  const [head, ...rest] = raw.split(/\r?\n\r?\n/);
  const body = rest.join("\n\n");
  const lines = head.split(/\r?\n/);
  const [method, target] = lines[0].split(" ");
  const headers = {}; let host = "";
  for (const l of lines.slice(1)) {
    const i = l.indexOf(":"); if (i < 0) continue;
    const k = l.slice(0,i).trim(), v = l.slice(i+1).trim();
    if (k.toLowerCase()==="host") host = v; else headers[k] = v;
  }
  return { method, url: `https://${host}${target}`, headers, body };
}
$("sendBtn").onclick = async () => {
  if (!CURRENT) return;
  $("sendBtn").disabled = true; $("respBox").value = "отправка…";
  const cookies = $("cookieInput").value.trim() || null;
  const use_session = $("useSessChk").checked;
  let payload = { cookies, use_session };
  if (editable) {
    const p = parseRawRequest($("reqBox").value);
    payload = { cookies, use_session, override_url:p.url, override_method:p.method, override_body:p.body, headers:p.headers };
  }
  try {
    const r = await fetch(`/api/combined/replay/${CURRENT.idx}`, {
      method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(payload) });
    const d = await r.json();
    if (!d.ok) { $("respBox").value = "ОШИБКА: " + d.error; $("respMeta").textContent = ""; }
    else {
      const via = d.via_agent ? " · 🤖 через браузер-агент" : (d.via_session ? " · via session" : "");
      $("respMeta").textContent = `${d.status} ${d.status_text} · ${d.length}B${via}`;
      const hdrs = Object.entries(d.headers).map(([k,v])=>`${k}: ${v}`).join("\n");
      $("respBox").value = `HTTP ${d.status} ${d.status_text}\n${hdrs}\n\n${d.body}`;
    }
  } catch (err) { $("respBox").value = "ошибка сети: " + err; }
  finally { $("sendBtn").disabled = false; }
};

// ------------------------------ tabs & wiring ------------------------------
function activateTab(name) {
  document.querySelectorAll(".tab").forEach(x => x.classList.toggle("active", x.dataset.tab === name));
  document.querySelectorAll(".tabBody").forEach(b => b.hidden = (b.id !== "tab-" + name));
}
document.querySelectorAll(".tab").forEach(t => t.onclick = () => activateTab(t.dataset.tab));
// gear menu (project / proxy / logout)
$("gearBtn").onclick = (e) => { e.stopPropagation(); $("gearMenu").hidden = !$("gearMenu").hidden; if (!$("gearMenu").hidden) loadPins(); };
document.addEventListener("click", (e) => { if (!e.target.closest(".gearWrap")) $("gearMenu").hidden = true; });
document.querySelectorAll(".srcTab").forEach(t => t.onclick = () => {
  document.querySelectorAll(".srcTab").forEach(x => x.classList.remove("active"));
  t.classList.add("active");
  document.querySelectorAll(".srcPane").forEach(p => p.hidden = true);
  $(`src-${t.dataset.src}`).hidden = false;
});
$("logoutBtn").onclick = async () => { await fetch("/api/logout",{method:"POST"}); location.reload(); };
$("saveBtn").onclick = saveProject;
$("clearBtn").onclick = async () => {
  const alsoSaved = confirm("Очистить текущий проект?\n\nOK — очистить и УДАЛИТЬ сохранённый файл (не подгрузится при входе).\nОтмена → потом спрошу про мягкую очистку.");
  let delete_saved = alsoSaved;
  if (!alsoSaved) {
    if (!confirm("Очистить только рабочую память (сохранённый проект оставить)?")) return;
    delete_saved = false;
  }
  const r = await fetch("/api/project/clear", { method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({ delete_saved }) });
  const d = await r.json();
  $("status").textContent = d.ok ? `проект очищен${d.deleted_saved ? " + файл удалён" : ""}` : "ошибка очистки";
  $("gearMenu").hidden = true;
  await refreshCombined();
};
$("proxyBtn").onclick = applyProxy;
$("rateBtn").onclick = applyRate;

// ------------------------------ agent pins ------------------------------
let PROXY_ACTIVE = false;
async function renderPins(pins) {
  const box = $("pinList");
  if (!pins || !pins.length) {
    box.innerHTML = `<div class="pinRow" style="color:var(--muted)">нет закреплённых доменов</div>`;
    return;
  }
  const state = PROXY_ACTIVE
    ? `<span style="color:var(--get)">● активно</span>`
    : `<span style="color:var(--del)" title="запусти прокси-браузер, чтобы пины работали">○ прокси выкл</span>`;
  box.innerHTML = `<div class="pinRow" style="opacity:.7"><span>📌 закреплено (${pins.length})</span>${state}</div>` +
    pins.map(h =>
      `<div class="pinRow"><span title="редирект с этого хоста заменяется агент-заглушкой">🔒 ${h}</span>` +
      `<button data-host="${h}" title="открепить">✕</button></div>`).join("");
  box.querySelectorAll("button[data-host]").forEach(b => b.onclick = async () => {
    await fetch("/api/agent/unpin", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ host: b.dataset.host }) });
    loadPins();
  });
}
async function loadPins() {
  try { const r = await fetch("/api/agent/pins"); if (r.ok) renderPins((await r.json()).pins); } catch(_){}
}
$("pinBtn").onclick = async () => {
  const host = $("pinInput").value.trim();
  if (!host) return;
  const btn = $("pinBtn"), orig = btn.textContent;
  btn.disabled = true; btn.textContent = "…";
  try {
    const r = await fetch("/api/agent/pin", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ host }) });
    let d = {}; try { d = await r.json(); } catch(_) {}
    if (r.ok) {
      $("pinInput").value = "";
      renderPins(d.pins);
      btn.textContent = "✓ закреплён";
      btn.style.color = "var(--get)"; btn.style.borderColor = "var(--get)";
    } else {
      const msg = r.status === 404 ? "нужен рестарт сервера (нет /api/agent/pin)" : (d.detail || ("HTTP " + r.status));
      btn.textContent = "✗ " + msg;
      btn.style.color = "var(--del)"; btn.style.borderColor = "var(--del)";
      $("pinList").innerHTML = `<div class="pinRow" style="color:var(--del)">пин не сохранён: ${msg}</div>`;
    }
  } catch (e) {
    btn.textContent = "✗ сеть"; btn.style.color = "var(--del)";
  }
  setTimeout(() => { btn.disabled = false; btn.textContent = orig;
    btn.style.color = ""; btn.style.borderColor = ""; }, 2200);
};
$("pinInput").addEventListener("keydown", e => { if (e.key==="Enter") $("pinBtn").click(); });
loadPins();

// ------------------------------ agent storage tokens ------------------------------
function short(s){ return s.length > 42 ? s.slice(0,20)+"…"+s.slice(-14) : s; }
async function loadTokens() {
  const box = $("tokBox");
  box.innerHTML = "<div class='pinRow'>загрузка…</div>";
  let d;
  try { const r = await fetch("/api/storage"); d = await r.json(); }
  catch(_) { box.innerHTML = "<div class='pinRow'>ошибка</div>"; return; }
  const origins = d.origins || [];
  if (!origins.length) { box.innerHTML = "<div class='pinRow'>пусто — открой цель в прокси-браузере</div>"; return; }
  let html = "";
  for (const o of origins) {
    html += `<div class="pinRow" style="opacity:.7"><span>🌐 ${o.origin}</span></div>`;
    if (!o.tokens.length) { html += `<div class="pinRow"><span style="color:var(--muted)">токенов не найдено (${o.ls_keys.length} ls / ${o.ss_keys.length} ss ключей)</span></div>`; continue; }
    for (const t of o.tokens) {
      const tag = t.jwt ? "JWT" : t.scope;
      html += `<div class="pinRow"><span title="${t.preview.replace(/"/g,'&quot;')}">🔑 ${t.key} <em style="color:var(--muted)">[${tag}]</em> ${short(t.token)}</span>` +
        `<button class="tokUse" data-tok="${encodeURIComponent(t.token)}" title="set_auth: Authorization: Bearer …" style="color:var(--get)">→ Bearer</button></div>`;
    }
  }
  box.innerHTML = html;
  box.querySelectorAll(".tokUse").forEach(b => b.onclick = async () => {
    const tok = decodeURIComponent(b.dataset.tok);
    await fetch("/api/settings/auth", { method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({ headers: { Authorization: "Bearer " + tok } }) });
    b.textContent = "✓ задан"; b.style.color = "var(--muted)";
  });
}
$("tokBtn").onclick = loadTokens;
$("katBtn").onclick = startKatana;
$("katStopBtn").onclick = stopKatana;
$("arcBtn").onclick = startArchive;
$("arcStopBtn").onclick = stopArchive;
$("dirBtn").onclick = startScanDir;
$("dirStopBtn").onclick = stopScanDir;
$("urlsBtn").onclick = startScanUrls;
$("urlsStopBtn").onclick = stopScanUrls;
$("urlsFile").onchange = parseUrlsFile;
$("xmlFile").onchange = () => {
  const f = $("xmlFile").files[0];
  $("xmlName").textContent = f ? `${f.name} (${(f.size/1048576).toFixed(1)} МБ)` : "";
};
$("analyzeBtn").onclick = () => startAnalyze();
$("applyFilter").onclick = () => { loadEndpoints(); updateLinks(); };
$("filterInput").addEventListener("keydown", e => { if (e.key==="Enter"){loadEndpoints();updateLinks();} });
$("staticChk").onchange = () => { loadEndpoints(); updateLinks(); };
loadMe(); loadRate(); refreshSession(); setInterval(refreshSession, 5000); resumeJob();
