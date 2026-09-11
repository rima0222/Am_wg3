let TOKEN = localStorage.getItem("awg_token") || "";
let pollTimer = null;
let currentConfigPeerId = null;
let currentAdjustPeerId = null;
const sparkHistory = [];
const SPARK_MAX_POINTS = 40;

function authHeaders(json = true) {
  const h = { Authorization: "Bearer " + TOKEN };
  if (json) h["Content-Type"] = "application/json";
  return h;
}

// ---------------- auth ----------------
async function doLogin() {
  const username = document.getElementById("login-username").value;
  const password = document.getElementById("login-password").value;
  const errEl = document.getElementById("login-error");
  errEl.textContent = "";
  try {
    const res = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const e = await res.json();
      errEl.textContent = e.detail || "Sign in failed";
      return;
    }
    const data = await res.json();
    TOKEN = data.token;
    localStorage.setItem("awg_token", TOKEN);
    showApp();
  } catch (e) {
    errEl.textContent = "Could not reach the server";
  }
}

function logout() {
  TOKEN = "";
  localStorage.removeItem("awg_token");
  clearInterval(pollTimer);
  document.getElementById("app-screen").classList.add("hidden");
  document.getElementById("login-screen").classList.remove("hidden");
}

function showApp() {
  document.getElementById("login-screen").classList.add("hidden");
  document.getElementById("app-screen").classList.remove("hidden");
  refreshAll();
  pollTimer = setInterval(refreshAll, 3000);
}

function refreshAll() {
  loadPeers();
  loadSystem();
}

// ---------------- formatting ----------------
function fmtBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + " " + units[i];
}

function fmtDate(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  return d.toISOString().slice(0, 10);
}

function daysLeft(ts) {
  if (!ts) return null;
  return Math.ceil((ts - Date.now() / 1000) / 86400);
}

// ---------------- system stats ----------------
async function loadSystem() {
  const res = await fetch("/api/system", { headers: authHeaders(false) });
  if (res.status === 401) return logout();
  const s = await res.json();

  document.getElementById("endpoint-label").textContent = `${s.endpoint}:${s.port} · ${s.interface}`;
  document.getElementById("stat-total").textContent = s.total_peers;
  document.getElementById("stat-online").textContent = s.online_peers;
  document.getElementById("stat-traffic").textContent = fmtBytes(s.total_traffic_bytes);

  setGauge("cpu", s.cpu_percent);
  setGauge("ram", s.ram_percent);

  sparkHistory.push(s.online_peers);
  if (sparkHistory.length > SPARK_MAX_POINTS) sparkHistory.shift();
  drawSparkline();
}

function setGauge(prefix, percent) {
  const fill = document.getElementById(`${prefix}-fill`);
  const value = document.getElementById(`${prefix}-value`);
  fill.style.width = Math.min(100, percent) + "%";
  fill.classList.remove("warn", "danger");
  if (percent >= 90) fill.classList.add("danger");
  else if (percent >= 70) fill.classList.add("warn");
  value.textContent = percent.toFixed(0) + "%";
}

function drawSparkline() {
  const svg = document.getElementById("sparkline");
  const w = 180, h = 34;
  const max = Math.max(1, ...sparkHistory);
  const step = w / Math.max(1, SPARK_MAX_POINTS - 1);
  const offset = SPARK_MAX_POINTS - sparkHistory.length;
  const points = sparkHistory
    .map((v, i) => {
      const x = (offset + i) * step;
      const y = h - (v / max) * (h - 4) - 2;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  svg.innerHTML = `
    <polyline points="${points}" fill="none" stroke="#57e6c8" stroke-width="1.5" />
    <text x="${w - 2}" y="10" font-family="IBM Plex Mono" font-size="9" fill="#7c879b" text-anchor="end">online</text>
  `;
}

// ---------------- peers ----------------
async function loadPeers() {
  const res = await fetch("/api/peers", { headers: authHeaders(false) });
  if (res.status === 401) return logout();
  const peers = await res.json();
  document.getElementById("users-count").textContent = `(${peers.length})`;
  const body = document.getElementById("peers-body");
  body.innerHTML = "";

  for (const p of peers) {
    const tr = document.createElement("tr");

    const pct = p.data_limit_bytes ? Math.min(100, (p.used_bytes / p.data_limit_bytes) * 100) : 0;
    let barClass = "";
    if (pct >= 95) barClass = "danger"; else if (pct >= 75) barClass = "warn";

    const dleft = daysLeft(p.expires_at);
    let expiryClass = "";
    if (dleft !== null) {
      if (dleft <= 0) expiryClass = "danger";
      else if (dleft <= 3) expiryClass = "warn";
    }

    tr.innerHTML = `
      <td>
        <div class="status-cell">
          <span class="status-dot ${p.online ? "online" : "offline"}"></span>
          ${p.online ? "online" : "offline"}
        </div>
      </td>
      <td class="name-cell">
        ${!p.enabled ? '<span class="disabled-tag">disabled</span>' : ""}
        <span class="name">${escapeHtml(p.name)}</span>
        ${p.note ? `<div class="note">${escapeHtml(p.note)}</div>` : ""}
      </td>
      <td class="mono">${p.ip_address}</td>
      <td>
        <div class="usage-bar-wrap">
          <span class="usage-numbers">${fmtBytes(p.used_bytes)} ${p.data_limit_bytes ? "/ " + fmtBytes(p.data_limit_bytes) : "· unlimited"}</span>
          ${p.data_limit_bytes ? `<div class="usage-track"><div class="usage-fill ${barClass}" style="width:${pct}%"></div></div>` : ""}
        </div>
      </td>
      <td class="expiry-cell ${expiryClass}">${p.expires_at ? fmtDate(p.expires_at) + (dleft !== null ? ` (${dleft}d)` : "") : "—"}</td>
      <td>
        <div class="actions-cell">
          <button class="btn-ghost btn-sm" onclick="viewConfig(${p.id})">Config</button>
          <button class="btn-ghost btn-sm" onclick="openAdjustModal(${p.id})">Adjust</button>
          <button class="btn-ghost btn-sm" onclick="resetPeer(${p.id})">Reset</button>
          <button class="btn-ghost btn-sm" onclick="toggleEnabled(${p.id}, ${!p.enabled})">${p.enabled ? "Disable" : "Enable"}</button>
          <button class="btn-danger btn-sm" onclick="deletePeer(${p.id})">Delete</button>
        </div>
      </td>`;
    body.appendChild(tr);
  }
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str || "";
  return div.innerHTML;
}

// ---------------- create ----------------
function openCreateModal() {
  document.getElementById("new-name").value = "";
  document.getElementById("new-note").value = "";
  document.getElementById("new-limit").value = "";
  document.getElementById("new-days").value = "";
  document.getElementById("create-modal").classList.remove("hidden");
}

function closeModal(id) {
  document.getElementById(id).classList.add("hidden");
}

async function submitCreate() {
  const name = document.getElementById("new-name").value.trim();
  if (!name) return alert("Please enter a name");
  const note = document.getElementById("new-note").value;
  const limitVal = document.getElementById("new-limit").value;
  const daysVal = document.getElementById("new-days").value;

  const body = { name, note };
  if (limitVal) body.data_limit_gb = parseFloat(limitVal);
  if (daysVal) {
    body.duration_days = parseInt(daysVal);
    body.expires_at = Math.floor(Date.now() / 1000) + parseInt(daysVal) * 86400;
  }

  const res = await fetch("/api/peers", { method: "POST", headers: authHeaders(), body: JSON.stringify(body) });
  if (!res.ok) { const e = await res.json(); return alert(e.detail || "Failed to create user"); }
  const data = await res.json();
  closeModal("create-modal");
  refreshAll();
  showConfigContent(data.id, data.config, data.portal_username, data.portal_password);
}

// ---------------- config / qr ----------------
async function viewConfig(peerId) {
  const res = await fetch(`/api/peers/${peerId}/config`, { headers: authHeaders(false) });
  const text = await res.text();
  showConfigContent(peerId, text, null, null);
}

function showConfigContent(peerId, text, portalUser, portalPass) {
  currentConfigPeerId = peerId;
  document.getElementById("config-text").value = text;

  const box = document.getElementById("portal-creds-box");
  if (portalUser) {
    box.innerHTML = `
      <div class="credential-box">
        <div><span class="k">Portal username:</span> ${portalUser}</div>
        <div><span class="k">Portal password:</span> ${portalPass}</div>
      </div>
      <p class="hint">Share these with the user — shown only once. They can use them at /portal to fetch their config and check usage if the server address ever changes.</p>`;
  } else {
    box.innerHTML = "";
  }

  fetch(`/api/peers/${peerId}/qr`, { headers: authHeaders(false) })
    .then((r) => r.blob())
    .then((blob) => { document.getElementById("config-qr").src = URL.createObjectURL(blob); });

  document.getElementById("config-modal").classList.remove("hidden");
}

function downloadConfig() {
  const text = document.getElementById("config-text").value;
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `peer-${currentConfigPeerId}.conf`;
  a.click();
}

// ---------------- enable/disable/delete/reset ----------------
async function toggleEnabled(id, enable) {
  await fetch(`/api/peers/${id}`, { method: "PUT", headers: authHeaders(), body: JSON.stringify({ enabled: enable }) });
  loadPeers();
}

async function deletePeer(id) {
  if (!confirm("Delete this user? This cannot be undone.")) return;
  await fetch(`/api/peers/${id}`, { method: "DELETE", headers: authHeaders(false) });
  refreshAll();
}

async function resetPeer(id) {
  if (!confirm("Reset usage and restart the time period for this user?")) return;
  const res = await fetch(`/api/peers/${id}/reset`, { method: "POST", headers: authHeaders(false) });
  if (!res.ok) { const e = await res.json(); return alert(e.detail || "Reset failed"); }
  loadPeers();
}

// ---------------- adjust plan ----------------
function openAdjustModal(id) {
  currentAdjustPeerId = id;
  document.getElementById("adjust-gb").value = "";
  document.getElementById("adjust-days").value = "";
  document.getElementById("adjust-modal").classList.remove("hidden");
}

async function submitAdjust() {
  const gb = document.getElementById("adjust-gb").value;
  const days = document.getElementById("adjust-days").value;
  const body = {};
  if (gb) body.add_gb = parseFloat(gb);
  if (days) body.add_days = parseInt(days);
  const res = await fetch(`/api/peers/${currentAdjustPeerId}/adjust`, {
    method: "POST", headers: authHeaders(), body: JSON.stringify(body),
  });
  if (!res.ok) { const e = await res.json(); return alert(e.detail || "Adjust failed"); }
  closeModal("adjust-modal");
  loadPeers();
}

// ---------------- settings ----------------
function openSettingsModal() {
  document.getElementById("settings-current-pass").value = "";
  document.getElementById("settings-new-user").value = "";
  document.getElementById("settings-new-pass").value = "";
  document.getElementById("settings-error").textContent = "";
  document.getElementById("settings-modal").classList.remove("hidden");
}

async function submitSettings() {
  const body = {
    current_password: document.getElementById("settings-current-pass").value,
    new_username: document.getElementById("settings-new-user").value || null,
    new_password: document.getElementById("settings-new-pass").value || null,
  };
  const res = await fetch("/api/admin/credentials", { method: "PUT", headers: authHeaders(), body: JSON.stringify(body) });
  if (!res.ok) {
    const e = await res.json();
    document.getElementById("settings-error").textContent = e.detail || "Update failed";
    return;
  }
  closeModal("settings-modal");
  alert("Credentials updated. Please sign in again.");
  logout();
}

// ---------------- backup / restore ----------------
function openBackupModal() {
  document.getElementById("restore-file").value = "";
  document.getElementById("backup-status").textContent = "";
  document.getElementById("backup-modal").classList.remove("hidden");
}

async function downloadBackup() {
  const res = await fetch("/api/backup", { headers: authHeaders(false) });
  const data = await res.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `awg-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
}

async function submitRestore() {
  const fileInput = document.getElementById("restore-file");
  const statusEl = document.getElementById("backup-status");
  if (!fileInput.files.length) { statusEl.textContent = "Choose a backup file first."; return; }
  const text = await fileInput.files[0].text();
  let json;
  try { json = JSON.parse(text); } catch (e) { statusEl.textContent = "Invalid JSON file."; return; }

  const res = await fetch("/api/backup/restore", { method: "POST", headers: authHeaders(), body: JSON.stringify(json) });
  const data = await res.json();
  if (!res.ok) { statusEl.textContent = data.detail || "Restore failed."; return; }
  statusEl.textContent = `Imported ${data.imported} user(s), skipped ${data.skipped} (already existed).`;
  refreshAll();
}

// ---------------- boot ----------------
if (TOKEN) showApp();
