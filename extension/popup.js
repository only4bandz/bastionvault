// Bastion popup — a thin view over the background service worker. It never
// runs crypto or holds the vault key; it asks the worker for item metadata and
// for a single secret only at the moment the user copies or fills it.

const app = document.getElementById("app");

// ── tiny helpers ──
const send = (msg) => chrome.runtime.sendMessage(msg);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function toast(text) {
  document.querySelector(".toast")?.remove();
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = text;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 2000);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied`);
    // Best-effort clipboard hygiene: clear after 25s if still ours.
    setTimeout(async () => {
      try {
        if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
      } catch {
        /* clipboard not readable; ignore */
      }
    }, 25000);
  } catch {
    toast("Copy failed");
  }
}

const ICON = {
  search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>',
  copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  user: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg>',
  fill: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h13"/><path d="m13 6 6 6-6 6"/></svg>',
  lock: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  gear: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 0 0-1.7-1L14.5 3h-5l-.4 2.6a7 7 0 0 0-1.7 1l-2.3-1-2 3.4 2 1.5a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.6h5l.4-2.6a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z"/></svg>',
};
const SHIELD = '<svg class="logo" viewBox="0 0 32 32" aria-hidden><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9a8cff"/><stop offset="1" stop-color="#5a47e6"/></linearGradient></defs><path fill="url(#bg)" d="M16 2l11 4v8.5c0 7-4.7 12.9-11 15.5C9.7 27.4 5 21.5 5 14.5V6l11-4z"/><circle cx="16" cy="14.5" r="3" fill="#0a0c12"/><path fill="#0a0c12" d="M14.6 15.5h2.8l1 5.5h-4.8z"/></svg>';

// ── current-site matching ──
function domainOf(value) {
  const c = (value || "").trim();
  if (!c.includes(".")) return null;
  let host = c;
  try {
    host = /^https?:\/\//i.test(c) ? new URL(c).hostname : c.split("/")[0];
  } catch {
    host = c.split("/")[0];
  }
  host = host.toLowerCase().replace(/^www\./, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(host) ? host : null;
}

function sameSite(a, b) {
  if (!a || !b) return false;
  return a === b || a.endsWith("." + b) || b.endsWith("." + a);
}

function avatarFor(it) {
  const domain = it.type === "card" ? it.cardBankDomain : domainOf(it.url || it.title);
  const letter = esc((it.title || "?")[0].toUpperCase());
  const color = colorFor(it.title || "");
  if (domain) {
    // The <img> error fallback is wired in JS (wireRows) — inline onerror= is
    // forbidden by the extension-page CSP.
    return `<div class="ico" style="background:${color}" data-letter="${letter}"><img src="https://icons.duckduckgo.com/ip3/${esc(domain)}.ico" alt="" /></div>`;
  }
  return `<div class="ico" style="background:${color}">${letter}</div>`;
}

function colorFor(title) {
  const palette = ["#7c6cff", "#3ad29f", "#ff7a59", "#47b5ff", "#f7b955", "#ff5d9e", "#19c3c3"];
  let h = 0;
  for (let i = 0; i < title.length; i++) h = (h * 31 + title.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}

function subtitleFor(it) {
  if (it.type === "card") return it.cardLast4 ? `•••• ${it.cardLast4}` : "Card";
  if (it.type === "note") return "Secure note";
  return it.username || it.url || "Login";
}

// ── rendering ──
let allItems = [];
let currentHost = null;

function rowHtml(it) {
  const fill = it.type === "login" && (it.username || it.hasPassword)
    ? `<button class="iconbtn" data-act="fill" data-id="${esc(it.id)}" title="Fill on this page">${ICON.fill}</button>`
    : "";
  const copyUser = it.username
    ? `<button class="iconbtn" data-act="user" data-id="${esc(it.id)}" title="Copy username">${ICON.user}</button>`
    : "";
  const copySecret = it.hasPassword
    ? `<button class="iconbtn" data-act="pass" data-id="${esc(it.id)}" title="Copy password">${ICON.copy}</button>`
    : it.type === "card" && it.cardLast4
    ? `<button class="iconbtn" data-act="card" data-id="${esc(it.id)}" title="Copy card number">${ICON.copy}</button>`
    : "";
  return `<div class="row" data-id="${esc(it.id)}">
    ${avatarFor(it)}
    <div class="meta"><div class="t">${esc(it.title)}</div><div class="s">${esc(subtitleFor(it))}</div></div>
    <div class="acts">${copyUser}${copySecret}${fill}</div>
  </div>`;
}

function renderVault(query = "") {
  const q = query.trim().toLowerCase();
  const match = (it) =>
    !q || [it.title, it.username, it.url].some((f) => (f || "").toLowerCase().includes(q));

  const filtered = allItems.filter(match);
  const onSite = q
    ? []
    : filtered.filter((it) => it.type === "login" && sameSite(domainOf(it.url || it.title), currentHost));
  const onSiteIds = new Set(onSite.map((i) => i.id));
  const rest = filtered.filter((it) => !onSiteIds.has(it.id));

  const sections = [];
  if (onSite.length) sections.push(`<div class="section-title">On this site</div>` + onSite.map(rowHtml).join(""));
  sections.push(
    `<div class="section-title">${q ? "Results" : "All items"} (${rest.length})</div>` +
      (rest.length ? rest.map(rowHtml).join("") : `<div class="empty">No items${q ? " match your search" : ""}.</div>`)
  );

  document.querySelector(".scroll").innerHTML = sections.join("");
  wireRows();
}

function wireRows() {
  // Broken favicons fall back to the letter tile (CSP-safe, no inline onerror).
  document.querySelectorAll(".ico[data-letter] img").forEach((img) => {
    img.addEventListener("error", () => {
      const tile = img.parentElement;
      tile.textContent = tile.dataset.letter || "?";
    });
  });
  document.querySelectorAll(".iconbtn[data-act]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const act = btn.dataset.act;
      const item = allItems.find((i) => i.id === id);
      if (act === "user") return copyText(item.username, "Username");
      if (act === "pass") {
        const r = await send({ type: "REVEAL", id, field: "password" });
        return r.ok ? copyText(r.value, "Password") : toast(r.error || "Error");
      }
      if (act === "card") {
        const r = await send({ type: "REVEAL", id, field: "cardNumber" });
        return r.ok ? copyText(r.value, "Card number") : toast(r.error || "Error");
      }
      if (act === "fill") {
        const r = await send({ type: "FILL", id });
        if (r.ok && r.filled) window.close();
        else toast(r.ok ? "No login field found on this page" : r.error || "Error");
      }
    });
  });
}

async function showVault(state) {
  const initial = esc((state.email || "?")[0].toUpperCase());
  app.innerHTML = `
    <div class="hdr">${SHIELD}<h1>Bastion</h1><div class="acct" title="${esc(state.email || "")}">${initial}</div></div>
    <div class="search-wrap"><div class="search">${ICON.search}<input id="q" placeholder="Search ${state.count} items" autofocus /></div></div>
    <div class="scroll"></div>
    <div class="bar">
      <button class="iconbtn" id="settings" title="Settings">${ICON.gear}</button>
      <div class="spacer"></div>
      <button class="iconbtn" id="lock" title="Lock vault">${ICON.lock}</button>
    </div>`;

  document.getElementById("lock").addEventListener("click", async () => {
    await send({ type: "LOCK" });
    showUnlock({ server: state.server });
  });
  document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  document.getElementById("q").addEventListener("input", (e) => renderVault(e.target.value));

  // current tab host (activeTab grants the URL while the popup is open)
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentHost = domainOf(tab?.url || "");
  } catch {
    currentHost = null;
  }

  const list = await send({ type: "LIST" });
  if (!list.ok) return showUnlock({ server: state.server });
  allItems = list.items;
  renderVault();
}

function showUnlock(state) {
  app.innerHTML = `
    <div class="auth">
      <div class="brand">${SHIELD}<b>BASTION</b></div>
      <h2>Unlock your vault</h2>
      <p class="sub">Decrypted only here, on your device. Server: <code>${esc(state.server)}</code></p>
      <div class="field"><label>Email</label><input class="input" id="email" type="email" placeholder="you@example.com" autofocus /></div>
      <div class="field"><label>Master password</label><input class="input" id="pw" type="password" /></div>
      <div class="field"><label>Secret Key</label><input class="input mono" id="sk" placeholder="A1-XXXXX-XXXXX-…" /></div>
      <div id="err"></div>
      <button class="btn btn-primary btn-block" id="go">Unlock</button>
      <div class="foot">
        New here? Create your vault in the Bastion app, then unlock here.<br/>
        <button class="link" id="opt">Change server</button>
      </div>
    </div>`;

  const errBox = document.getElementById("err");
  const go = document.getElementById("go");
  document.getElementById("opt").addEventListener("click", () => chrome.runtime.openOptionsPage());

  async function attempt() {
    errBox.innerHTML = "";
    const email = document.getElementById("email").value.trim();
    const pw = document.getElementById("pw").value;
    const sk = document.getElementById("sk").value.trim();
    if (!email || !pw || !sk) {
      errBox.innerHTML = `<div class="callout">Email, master password and Secret Key are all required.</div>`;
      return;
    }
    go.disabled = true;
    go.textContent = "Unlocking…";
    const r = await send({ type: "UNLOCK", email, password: pw, secretKey: sk });
    if (r.ok) {
      const state2 = await send({ type: "STATE" });
      showVault(state2);
    } else {
      errBox.innerHTML = `<div class="callout">${esc(r.error || "Could not unlock.")}</div>`;
      go.disabled = false;
      go.textContent = "Unlock";
    }
  }
  go.addEventListener("click", attempt);
  document.getElementById("sk").addEventListener("keydown", (e) => e.key === "Enter" && attempt());
}

// ── boot ──
(async () => {
  try {
    const state = await send({ type: "STATE" });
    if (state.locked) showUnlock(state);
    else showVault(state);
  } catch (e) {
    showUnlock({ server: "(unknown)" });
  }
})();
