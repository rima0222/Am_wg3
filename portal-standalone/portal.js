/*
 * This page can be served two ways:
 *  1. From the panel itself, at http://SERVER:PORT/portal/  (same-origin API calls)
 *  2. As a standalone static site (e.g. GitHub Pages), in which case it reads
 *     ./mirrors.json for a list of candidate server addresses and tries each
 *     one until it finds one that responds. This means if a server's IP gets
 *     blocked, the admin can spin up a new server, restore the JSON backup,
 *     add its address to mirrors.json, and users can still reach their
 *     account from the very same page/link without reinstalling anything.
 *
 * Honesty note: this does not make the panel itself unblockable — it only
 * removes the need to redistribute a new link/app to every user. If the
 * page's own hosting (e.g. GitHub Pages) is blocked too, this doesn't help.
 */
const LS_BASE = "awg_portal_api_base";
const LS_TOKEN = "awg_portal_token";

async function probe(base) {
  try {
    const res = await fetch(`${base}/api/system`, { method: "GET", cache: "no-store" });
    // 401 still means "server is reachable and speaking our API"
    return res.status === 401 || res.ok;
  } catch (e) {
    return false;
  }
}

async function resolveApiBase() {
  const candidates = [];
  const cached = localStorage.getItem(LS_BASE);
  if (cached !== null) candidates.push(cached);
  if (!candidates.includes("")) candidates.push(""); // same-origin

  try {
    const res = await fetch("./mirrors.json", { cache: "no-store" });
    if (res.ok) {
      const data = await res.json();
      for (const m of data.mirrors || []) {
        const clean = m.replace(/\/$/, "");
        if (!candidates.includes(clean)) candidates.push(clean);
      }
    }
  } catch (e) {
    /* no mirrors.json present — fine, same-origin only */
  }

  for (const base of candidates) {
    if (await probe(base)) {
      localStorage.setItem(LS_BASE, base);
      return base;
    }
  }
  return candidates[0] || "";
}

function show(id) {
  for (const v of ["login-view", "status-view", "config-view"]) {
    document.getElementById(v).classList.toggle("hidden", v !== id);
  }
}

async function portalLogin() {
  const username = document.getElementById("p-username").value.trim();
  const password = document.getElementById("p-password").value;
  const errEl = document.getElementById("p-error");
  errEl.textContent = "";
  document.getElementById("p-source").textContent = "Looking for your server…";

  const base = await resolveApiBase();
  document.getElementById("p-source").textContent = "";

  try {
    const res = await fetch(`${base}/api/portal/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({}));
      errEl.textContent = e.detail || "Invalid username or password";
      return;
    }
    const data = await res.json();
    localStorage.setItem(LS_TOKEN, data.token);
    localStorage.setItem(LS_BASE, base);
    await loadStatus();
  } catch (e) {
    errEl.textContent = "Could not reach any known server.";
  }
}

function portalLogout() {
  localStorage.removeItem(LS_TOKEN);
  show("login-view");
}

function authHeaders() {
  return { Authorization: "Bearer " + localStorage.getItem(LS_TOKEN) };
}

function fmtBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = bytes;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return v.toFixed(1) + " " + units[i];
}

let lastStatus = null;

async function loadStatus() {
  const base = localStorage.getItem(LS_BASE) || "";
  try {
    const res = await fetch(`${base}/api/portal/status`, { headers: authHeaders() });
    if (res.status === 401) { portalLogout(); return; }
    if (!res.ok) throw new Error("bad status");
    const s = await res.json();
    lastStatus = s;
    renderStatus(s);
    show("status-view");
  } catch (e) {
    document.getElementById("p-error").textContent = "Lost connection to the server — trying to reconnect…";
    const newBase = await resolveApiBase();
    if (newBase !== base) {
      loadStatus();
    }
  }
}

function renderStatus(s) {
  document.getElementById("p-name").textContent = s.name;
  const dot = document.getElementById("p-dot");
  dot.classList.toggle("online", s.online);
  document.getElementById("p-online-label").textContent = s.online ? "online" : "offline";

  const usageText = document.getElementById("p-usage-text");
  const usageFill = document.getElementById("p-usage-fill");
  if (s.data_limit_bytes) {
    const pct = Math.min(100, (s.used_bytes / s.data_limit_bytes) * 100);
    usageFill.style.width = pct + "%";
    usageFill.classList.remove("warn", "danger");
    if (pct >= 95) usageFill.classList.add("danger");
    else if (pct >= 75) usageFill.classList.add("warn");
    usageText.textContent = `${fmtBytes(s.used_bytes)} / ${fmtBytes(s.data_limit_bytes)} (${fmtBytes(Math.max(0, s.remaining_bytes))} left)`;
  } else {
    usageFill.style.width = "100%";
    usageText.textContent = `${fmtBytes(s.used_bytes)} used · unlimited`;
  }

  const timeText = document.getElementById("p-time-text");
  timeText.textContent = s.remaining_days !== null ? `${s.remaining_days} day(s) left` : "unlimited";
}

async function showConfig() {
  const base = localStorage.getItem(LS_BASE) || "";
  const res = await fetch(`${base}/api/portal/config`, { headers: authHeaders() });
  const text = await res.text();
  document.getElementById("p-config-text").value = text;
  fetch(`${base}/api/portal/qr`, { headers: authHeaders() })
    .then((r) => r.blob())
    .then((blob) => { document.getElementById("p-qr").src = URL.createObjectURL(blob); });
  show("config-view");
}

function backToStatus() { show("status-view"); }

function downloadPortalConfig() {
  const text = document.getElementById("p-config-text").value;
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "my-vpn.conf";
  a.click();
}

// ---------------- boot ----------------
if (localStorage.getItem(LS_TOKEN)) {
  loadStatus();
} else {
  show("login-view");
}
