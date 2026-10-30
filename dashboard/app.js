/* PHANTOM dashboard - vanilla JS, talks only to the same-origin FastAPI server. */
"use strict";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => [...document.querySelectorAll(sel)];
const POLL_MS = 3000;

const state = {
  admin: "",
  severity: "",
  lastEventId: 0,
  kpis: {},
  online: null,
};

try { state.admin = sessionStorage.getItem("phantom-admin") || ""; } catch (_) { /* storage blocked */ }

// ------------------------------------------------------------------ utilities
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
const fmtTime = (ts) => new Date(ts * 1000).toLocaleTimeString([], { hour12: false });
const fmtDate = (ts) => new Date(ts * 1000).toLocaleDateString([], { year: "numeric", month: "short", day: "numeric" });
const shortHash = (h) => (h ? `${h.slice(0, 12)}…${h.slice(-6)}` : "—");

function fmtUptime(s) {
  s = Math.floor(s);
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${h}h` : h ? `${h}h ${m}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}

let toastTimer;
function toast(message, kind = "") {
  const el = $("#toast");
  el.textContent = message;
  el.className = `toast show ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 3800);
}

async function api(path, { method = "GET", body, admin = false } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (admin) headers["X-Admin-Secret"] = state.admin;
  try {
    const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
    let data = {};
    try { data = await res.json(); } catch (_) { /* empty body */ }
    return { ok: res.ok, status: res.status, data };
  } catch (err) {
    return { ok: false, status: 0, data: { message: "License server unreachable" } };
  }
}

function needAdmin() {
  if (state.admin) return true;
  toast("Enter the admin secret (top right) to run administrative actions.", "warn");
  $("#admin-secret").focus();
  return false;
}

function adminError(res) {
  if (res.status === 401 || res.status === 403) {
    setAdmin("");
    toast("Admin secret rejected by the server.", "bad");
    return true;
  }
  return false;
}

async function withBusy(btn, fn) {
  if (btn) btn.disabled = true;
  try { await fn(); } finally { if (btn) btn.disabled = false; }
}

// base64url helpers for the client-side "forge" demo
const b64urlDecode = (s) => {
  const str = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  return decodeURIComponent(escape(atob(str)));
};
const b64urlEncode = (s) => btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function peekClaims(token) {
  try { return JSON.parse(b64urlDecode(token.trim().split(".")[1])); } catch (_) { return null; }
}

// ------------------------------------------------------------------ admin
function setAdmin(secret) {
  state.admin = secret;
  try { secret ? sessionStorage.setItem("phantom-admin", secret) : sessionStorage.removeItem("phantom-admin"); } catch (_) {}
  const chip = $("#admin-state");
  chip.textContent = secret ? "Admin unlocked" : "Admin locked";
  chip.className = `chip ${secret ? "chip-ok" : "chip-muted"}`;
  $("#admin-btn").textContent = secret ? "Lock" : "Unlock admin";
  $("#admin-secret").value = "";
  $("#admin-secret").style.display = secret ? "none" : "";
  loadRegistry();
}

$("#admin-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  if (state.admin) { setAdmin(""); return; }
  const secret = $("#admin-secret").value.trim();
  if (!secret) return toast("Type the admin secret first.", "warn");
  state.admin = secret;
  const res = await api("/api/licenses?limit=1", { admin: true });
  if (res.ok) { setAdmin(secret); toast("Admin unlocked.", "ok"); }
  else { state.admin = ""; toast(res.status === 429 ? "Too many attempts - wait a minute." : "Invalid admin secret.", "bad"); }
});

// ------------------------------------------------------------------ license operations
function showClaims(token) {
  const box = $("#license-claims");
  const c = peekClaims(token || "");
  if (!c) { box.innerHTML = token ? '<span class="chip chip-bad">Not a decodable PHM1 key</span>' : ""; return; }
  const exp = c.expires_at ? fmtDate(c.expires_at) : "?";
  box.innerHTML = [
    `<span class="chip chip-accent">${esc(c.license_id)}</span>`,
    `<span class="chip chip-muted">${esc(c.product_id)}</span>`,
    `<span class="chip chip-muted">licensee: ${esc(c.licensee)}</span>`,
    `<span class="chip ${c.expires_at * 1000 < Date.now() ? "chip-bad" : "chip-muted"}">expires ${esc(exp)}</span>`,
    `<span class="chip chip-muted">key ${esc(c.key_id || "?")}</span>`,
  ].join("");
}

function setLicense(token) {
  $("#license-key").value = token;
  showClaims(token);
}

function showVerdict(res, label) {
  const v = $("#verdict");
  const d = res.data || {};
  const valid = res.ok && d.valid;
  v.className = `verdict ${valid ? "verdict-ok" : "verdict-bad"}`;
  void v.offsetWidth; v.classList.add("verdict-flash");
  $("#verdict-badge").textContent = valid ? "ACCESS GRANTED" : "ACCESS DENIED";
  $("#verdict-code").textContent = `${label} · HTTP ${res.status || "—"} · ${d.code || d.error || "NO_RESPONSE"}`;
  $("#verdict-msg").textContent = d.message || "No response from license server.";
  refresh();
}

async function issue(days, licensee) {
  const res = await api("/api/licenses/generate", { method: "POST", admin: true, body: { licensee, valid_days: days } });
  if (adminError(res)) return null;
  if (!res.ok) { toast(res.data.message || "Could not generate license.", "bad"); return null; }
  return res.data;
}

async function verify(token, label) {
  const res = await api("/api/licenses/verify", { method: "POST", body: { license_key: token, client_id: "dashboard" } });
  showVerdict(res, label);
  return res;
}

$("#gen-form").addEventListener("submit", (e) => {
  e.preventDefault();
  if (!needAdmin()) return;
  withBusy(e.submitter, async () => {
    const days = parseInt($("#gen-days").value, 10);
    const lic = await issue(Number.isFinite(days) ? days : 30, $("#gen-licensee").value.trim() || "Demo User");
    if (!lic) return;
    setLicense(lic.license_key);
    toast(`Issued ${lic.license.license_id} (${lic.license.status}).`, "ok");
    loadRegistry(); refresh();
  });
});

$("#license-key").addEventListener("input", (e) => showClaims(e.target.value));

$("#copy-btn").addEventListener("click", async () => {
  const value = $("#license-key").value.trim();
  if (!value) return toast("Nothing to copy yet.", "warn");
  try { await navigator.clipboard.writeText(value); toast("License key copied. Activate it in the client container.", "ok"); }
  catch (_) { $("#license-key").select(); toast("Press Ctrl+C to copy.", "warn"); }
});

const licenseActions = {
  async verify() {
    const token = $("#license-key").value.trim();
    if (!token) return toast("Generate or paste a license first.", "warn");
    await verify(token, "Verify");
  },
  async forge() {
    // Simulates a cracker editing the license payload (extend expiry, rename licensee)
    // while keeping the original signature. Ed25519 verification must fail.
    let token = $("#license-key").value.trim();
    if (!peekClaims(token)) {
      if (!needAdmin()) return;
      const lic = await issue(30, "Forge Victim"); if (!lic) return; token = lic.license_key;
    }
    const [prefix, payload, sig] = token.split(".");
    const claims = JSON.parse(b64urlDecode(payload));
    claims.expires_at = 4102444800; // year 2100
    claims.licensee = `${claims.licensee} (cracked)`;
    const sorted = Object.fromEntries(Object.keys(claims).sort().map((k) => [k, claims[k]]));
    const forged = `${prefix}.${b64urlEncode(JSON.stringify(sorted))}.${sig}`;
    setLicense(forged);
    toast("Payload edited: expiry pushed to 2100, signature left unchanged.", "warn");
    await verify(forged, "Forged license");
  },
  async expired() {
    if (!needAdmin()) return;
    const lic = await issue(-1, "Expired Demo"); if (!lic) return;
    setLicense(lic.license_key);
    await verify(lic.license_key, "Expired license");
    loadRegistry();
  },
  async revoke() {
    if (!needAdmin()) return;
    let token = $("#license-key").value.trim();
    let claims = peekClaims(token);
    if (!claims || String(claims.licensee).endsWith("(cracked)")) {
      const lic = await issue(30, "Revocation Demo"); if (!lic) return;
      token = lic.license_key; claims = lic.license; setLicense(token);
    }
    const res = await api("/api/licenses/revoke", { method: "POST", admin: true, body: { license_id: claims.license_id, reason: "Revoked from dashboard demo" } });
    if (adminError(res)) return;
    if (!res.ok && res.status !== 409) toast(res.data.message || "Revocation failed.", "bad");
    else toast(`${claims.license_id} revoked on the server.`, "warn");
    await verify(token, "Revoked license");
    loadRegistry();
  },
  async garbage() {
    await verify("PHM1.this-is-not.a-real-license", "Malformed key");
  },
};

$$("[data-action]").forEach((btn) =>
  btn.addEventListener("click", () => withBusy(btn, () => licenseActions[btn.dataset.action]())));

// ------------------------------------------------------------------ integrity lab
function renderIntegrity(report) {
  const status = $("#int-status");
  const pass = report.status === "PASS";
  const s = report.summary;
  status.className = `int-status ${pass ? "ok" : "bad"}`;
  status.textContent = pass
    ? `INTEGRITY VERIFIED - ${s.ok} file(s) match the signed SHA-256 manifest`
    : `TAMPERING DETECTED - ${s.modified} modified, ${s.missing} missing, ${s.unexpected} unexpected`;
  const chip = { OK: "chip-ok", MODIFIED: "chip-bad", MISSING: "chip-bad", UNEXPECTED: "chip-warn" };
  $("#int-files").innerHTML = report.files.map((f) => `
    <tr>
      <td class="mono">${esc(f.path)}</td>
      <td><span class="chip ${chip[f.status]}">${esc(f.status)}</span></td>
      <td class="hash" title="${esc(f.expected || "")}">${esc(shortHash(f.expected))}</td>
      <td class="hash ${f.status === "OK" ? "" : "diff"}" title="${esc(f.actual || "")}">${esc(shortHash(f.actual))}</td>
    </tr>`).join("");
}

async function runIntegrity() {
  const res = await api("/api/integrity/verify", { method: "POST" });
  if (!res.ok) return toast(res.data.message || "Integrity check failed to run.", "bad");
  renderIntegrity(res.data);
  toast(res.data.status === "PASS" ? "Integrity verified." : "Tampering detected!", res.data.status === "PASS" ? "ok" : "bad");
  refresh();
}

$$("[data-int]").forEach((btn) => btn.addEventListener("click", () => withBusy(btn, async () => {
  const action = btn.dataset.int;
  if (action === "verify") return runIntegrity();
  if (!needAdmin()) return;
  const res = await api("/api/integrity/simulate", { method: "POST", admin: true, body: { action } });
  if (adminError(res)) return;
  if (!res.ok) return toast(res.data.message || "Simulation failed.", "bad");
  toast(res.data.message, action === "restore" ? "ok" : "warn");
  await runIntegrity();
})));

// ------------------------------------------------------------------ registry
async function loadRegistry() {
  const body = $("#registry");
  if (!state.admin) { body.innerHTML = '<tr><td colspan="5" class="empty">Unlock admin to view the registry</td></tr>'; return; }
  const res = await api("/api/licenses?limit=50", { admin: true });
  if (adminError(res) || !res.ok) return;
  const rows = res.data.licenses;
  if (!rows.length) { body.innerHTML = '<tr><td colspan="5" class="empty">No licenses issued yet</td></tr>'; return; }
  const chip = { active: "chip-ok", expired: "chip-warn", revoked: "chip-bad" };
  body.innerHTML = rows.map((r) => `
    <tr>
      <td class="mono">${esc(r.license_id)}</td>
      <td>${esc(r.licensee)}</td>
      <td>${esc(fmtDate(r.expires_at))}</td>
      <td><span class="chip ${chip[r.status]}">${esc(r.status)}</span></td>
      <td>${r.status === "revoked" ? "" : `<button class="btn btn-small btn-ghost" data-revoke="${esc(r.license_id)}">Revoke</button>`}</td>
    </tr>`).join("");
}

$("#registry").addEventListener("click", async (e) => {
  const id = e.target.dataset && e.target.dataset.revoke;
  if (!id) return;
  const res = await api("/api/licenses/revoke", { method: "POST", admin: true, body: { license_id: id, reason: "Revoked from registry" } });
  if (adminError(res)) return;
  toast(res.ok ? `${id} revoked.` : res.data.message, res.ok ? "warn" : "bad");
  loadRegistry(); refresh();
});

// ------------------------------------------------------------------ live monitoring
function setCard(id, cls, value, note) {
  const card = $(id);
  card.className = `status-card ${cls}`;
  card.querySelector(".status-value").textContent = value;
  if (note) card.querySelector(".status-note").textContent = note;
}

function setKpi(id, value) {
  const el = $(id);
  if (state.kpis[id] !== undefined && state.kpis[id] !== value) {
    el.classList.remove("bump"); void el.offsetWidth; el.classList.add("bump");
  }
  state.kpis[id] = value;
  el.textContent = value;
}

function renderChart(timeline) {
  const svg = $("#chart");
  const W = 600, H = 180, pad = 6, n = timeline.length;
  const max = Math.max(4, ...timeline.map((b) => b.valid + b.failed + b.tamper));
  const bw = W / n;
  let out = "";
  for (let i = 1; i <= 3; i++) out += `<line class="grid-line" x1="0" x2="${W}" y1="${(H * i) / 4}" y2="${(H * i) / 4}"/>`;
  timeline.forEach((b, i) => {
    let y = H;
    const x = i * bw + pad / 2, w = bw - pad;
    const label = `${fmtTime(b.minute)} - valid ${b.valid}, rejected ${b.failed}, tamper ${b.tamper}`;
    out += `<g><title>${esc(label)}</title>`;
    [["valid", "var(--ok)"], ["failed", "var(--warn)"], ["tamper", "var(--bad)"]].forEach(([k, color]) => {
      if (!b[k]) return;
      const h = Math.max(2, (b[k] / max) * (H - 10));
      y -= h;
      out += `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="2" fill="${color}"/>`;
    });
    if (y === H) out += `<rect x="${x}" y="${H - 2}" width="${w}" height="2" rx="1" fill="var(--line)"/>`;
    out += `</g>`;
  });
  svg.innerHTML = out;
}

function renderClients(clients) {
  const box = $("#clients");
  if (!clients.length) {
    box.innerHTML = '<div class="empty">No client has checked in yet. Start it with <span class="mono">docker compose up -d</span>.</div>';
    return;
  }
  box.innerHTML = clients.map((c) => {
    const d = c.details || {}, env = d.environment || {};
    const live = c.online ? (c.status === "RUNNING" ? "chip-ok" : "chip-bad") : "chip-muted";
    return `<div class="client">
      <div class="client-top">
        <span class="client-id">${esc(c.client_id)}</span>
        <span class="chip ${live}">${c.online ? esc(c.status) : "OFFLINE"}</span>
      </div>
      <div class="client-meta">
        <span class="chip ${d.license_code === "VALID" ? "chip-ok" : "chip-bad"}">license ${esc(d.license_code || "?")}</span>
        <span class="chip ${d.integrity === "PASS" ? "chip-ok" : "chip-bad"}">integrity ${esc(d.integrity || "?")}</span>
        ${env.debugger_detected ? `<span class="chip chip-warn">debugger: ${esc((env.indicators || []).join(", "))}</span>` : '<span class="chip chip-muted">no debugger</span>'}
        ${(d.local_reasons || []).map((r) => `<span class="chip chip-bad">${esc(r)}</span>`).join("")}
        ${env.container ? '<span class="chip chip-accent">container</span>' : ""}
        ${env.kernel ? `<span class="chip chip-muted" title="Containers share the host kernel">kernel ${esc(env.kernel)}</span>` : ""}
        <span class="chip chip-muted">seen ${esc(fmtTime(c.last_seen))}</span>
      </div>
    </div>`;
  }).join("");
}

async function refresh() {
  const res = await api("/api/stats");
  if (!res.ok) {
    state.online = false;
    $("#server-pill").className = "pill pill-bad";
    $("#server-pill-text").textContent = "SERVER OFFLINE";
    setCard("#card-server", "bad", "OFFLINE", "Health check failing - is the container running?");
    return;
  }
  const s = res.data;
  if (state.online === false) toast("License server is back online.", "ok");
  state.online = true;

  $("#server-pill").className = "pill pill-ok";
  $("#server-pill-text").textContent = "SERVER ONLINE";
  $("#meta-env").textContent = s.server.environment;
  $("#meta-key").textContent = s.server.key_fingerprint;
  $("#meta-uptime").textContent = fmtUptime(s.server.uptime_seconds);
  setCard("#card-server", "ok", "ONLINE", `v${s.server.version} · ${s.server.product_id} · ${s.server.strict_registry ? "strict" : "stateless"} registry`);

  const tampered = s.integrity.workspace !== "PASS" || s.integrity.last_status === "FAIL";
  setCard("#card-protection", tampered ? "bad" : "ok", tampered ? "TAMPERED" : "PROTECTED",
    tampered ? `Integrity failure on ${s.integrity.last_target || "server workspace"}` : `${s.integrity.trusted_files} files match signed manifest`);

  const live = s.clients.filter((c) => c.online);
  const locked = live.filter((c) => c.status !== "RUNNING").length;
  if (!live.length) setCard("#card-clients", "warn", "NONE ONLINE", "Start the phantom-client container");
  else setCard("#card-clients", locked ? "bad" : "ok", `${live.length - locked} RUNNING · ${locked} LOCKED`, "Heartbeat via online license verification");

  const codes = s.verifications.by_code;
  setKpi("#k-active", s.licenses.active);
  setKpi("#k-expired", s.licenses.expired);
  setKpi("#k-revoked", s.licenses.revoked);
  setKpi("#k-total", s.verifications.total);
  setKpi("#k-failed", s.verifications.failed);
  setKpi("#k-invalid", (codes.BAD_SIGNATURE || 0) + (codes.MALFORMED || 0));
  setKpi("#k-tamper", s.integrity.failures);
  setKpi("#k-auth", s.security.auth_failures);

  $("#codes").innerHTML = Object.keys(codes).length
    ? Object.entries(codes).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<span class="chip chip-warn">${esc(k)} × ${v}</span>`).join("")
    : '<span class="chip chip-muted">No rejected verifications yet</span>';

  $("#f-int-last").innerHTML = s.integrity.last_status
    ? `<span class="chip ${s.integrity.last_status === "PASS" ? "chip-ok" : "chip-bad"}">${esc(s.integrity.last_status)}</span>` : "—";
  $("#f-int-target").textContent = s.integrity.last_checked_at ? `${s.integrity.last_target} @ ${fmtTime(s.integrity.last_checked_at)}` : "—";
  $("#f-int-ws").innerHTML = `<span class="chip ${s.integrity.workspace === "PASS" ? "chip-ok" : "chip-bad"}">${esc(s.integrity.workspace)}</span>`;
  $("#f-int-files").textContent = s.integrity.trusted_files;
  $("#f-int-checks").textContent = `${s.integrity.checks} (${s.integrity.failures} failed)`;
  $("#f-rate").textContent = s.security.rate_limited;

  renderChart(s.timeline);
  renderClients(s.clients);
  loadEvents();
}

async function loadEvents() {
  const q = new URLSearchParams({ limit: "100" });
  if (state.severity) q.set("severity", state.severity);
  const res = await api(`/api/events?${q}`);
  if (!res.ok) return;
  const events = res.data.events;
  const sev = { info: "chip-muted", warning: "chip-warn", critical: "chip-bad" };
  const newest = events.length ? events[0].id : 0;
  $("#events").innerHTML = events.length ? events.map((e) => `
    <tr class="${e.id > state.lastEventId && state.lastEventId ? "fresh" : ""}">
      <td>${esc(fmtTime(e.ts))}</td>
      <td><span class="chip ${sev[e.severity] || "chip-muted"}">${esc(e.severity)}</span></td>
      <td><span class="chip chip-accent">${esc(e.category)}</span></td>
      <td>${esc(e.source)}</td>
      <td>${esc(e.message)}</td>
    </tr>`).join("") : '<tr><td colspan="5" class="empty">No events for this filter</td></tr>';
  state.lastEventId = Math.max(state.lastEventId, newest);
}

$$("[data-sev]").forEach((btn) => btn.addEventListener("click", () => {
  $$("[data-sev]").forEach((b) => b.classList.toggle("active", b === btn));
  state.severity = btn.dataset.sev;
  loadEvents();
}));

setInterval(() => { if ($("#live").checked && !document.hidden) refresh(); }, POLL_MS);
setAdmin(state.admin);
refresh();
