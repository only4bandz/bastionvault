// Bastion popup — a thin view over the background service worker. It never
// runs crypto or holds the vault key; it asks the worker for item metadata and
// for a single secret only at the moment the user copies or fills it.

import { domainOf, matchesSite } from "./lib/match.js";
import { generatePassword } from "./lib/generator.js";
import { initTheme } from "./lib/theme.js";
import { copyToastMessage } from "./lib/clipboard-clear.js";

initTheme(); // apply dark/light before first paint

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
  } catch {
    toast("Copy failed");
    return;
  }
  // The wipe is owned by the background/offscreen document, NOT this popup:
  // the popup closes on click-away (FILL even calls window.close()), so a
  // timer here would never fire. We hand the schedule to the worker and send
  // no plaintext — only the signal. See offscreen.js.
  //
  // Announce the auto-clear only once the worker confirms the timer is armed.
  // Toasting "clears in 12s" first and discarding every failure meant a
  // secret could sit on the clipboard indefinitely while the user believed
  // it had been wiped.
  const ack = await send({ type: "CLIP_CLEAR" }).catch(() => null);
  toast(copyToastMessage(label, ack));
}

const IC_CHECK =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="m5 13 4 4L19 7"/></svg>';

// Momentarily swap an action button's icon to a green check (copy feedback).
function flashCheck(btn) {
  if (!btn || btn.dataset.flashing) return;
  const orig = btn.innerHTML;
  btn.dataset.flashing = "1";
  btn.innerHTML = IC_CHECK;
  btn.classList.add("ok");
  setTimeout(() => {
    btn.innerHTML = orig;
    btn.classList.remove("ok");
    delete btn.dataset.flashing;
  }, 900);
}

const ICON = {
  search: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="m20 20-3-3"/></svg>',
  copy: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  user: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg>',
  fill: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h13"/><path d="m13 6 6 6-6 6"/></svg>',
  lock: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
  gear: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19 12a7 7 0 0 0-.1-1l2-1.5-2-3.4-2.3 1a7 7 0 0 0-1.7-1L14.5 3h-5l-.4 2.6a7 7 0 0 0-1.7 1l-2.3-1-2 3.4 2 1.5a7 7 0 0 0 0 2l-2 1.5 2 3.4 2.3-1a7 7 0 0 0 1.7 1l.4 2.6h5l.4-2.6a7 7 0 0 0 1.7-1l2.3 1 2-3.4-2-1.5c.1-.3.1-.7.1-1z"/></svg>',
  back: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 6-6 6 6 6"/></svg>',
  eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3l18 18"/><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"/><path d="M9.4 5.2A10 10 0 0 1 22 12a13 13 0 0 1-2.4 3.2M6.3 6.3A13 13 0 0 0 2 12s3.5 7 10 7a10 10 0 0 0 3-.5"/></svg>',
  link: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/></svg>',
  shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3z"/><path d="m9 12 2 2 4-4"/></svg>',
  regen: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>',
  key: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="15" r="4"/><path d="m10.85 12.15 8.15-8.15"/><path d="m18 5 2 2"/><path d="m15 8 2 2"/></svg>',
  send: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4 20-7z"/></svg>',
  plus: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 5v14"/><path d="M5 12h14"/></svg>',
  trash: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18"/><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>',
  contacts: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.5 3-5.5 6-5.5s6 2 6 5.5"/><path d="M16 4a3.5 3.5 0 0 1 0 7"/><path d="M18.5 14.5c2 .8 3.5 2.4 3.5 5"/></svg>',
  inbox: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 6h14l2 6v6a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1v-6z"/></svg>',
  lockmini: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
};
const SHIELD = '<svg class="logo" viewBox="0 0 32 32" aria-hidden><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9a8cff"/><stop offset="1" stop-color="#5a47e6"/></linearGradient></defs><path fill="url(#bg)" d="M16 2l11 4v8.5c0 7-4.7 12.9-11 15.5C9.7 27.4 5 21.5 5 14.5V6l11-4z"/><circle cx="16" cy="14.5" r="3" fill="#0a0c12"/><path fill="#0a0c12" d="M14.6 15.5h2.8l1 5.5h-4.8z"/></svg>';

function avatarFor(it) {
  const domain = it.type === "card" ? it.cardBankDomain : domainOf(it.url || it.title);
  const letter = esc((it.title || "?")[0].toUpperCase());
  const color = colorFor(it.title || "");
  if (domain) {
    // Favicon comes from Chrome's LOCAL cache via the _favicon API — NO request
    // to any third party, so the set of sites in the vault is never disclosed
    // (a zero-knowledge requirement; the old Google s2 fetch leaked every
    // domain). Clean white tile (NordPass-like) so transparent logos don't
    // bleed our color; falls back to the letter tile in wireFavicons (inline
    // onerror= is forbidden by the extension-page CSP).
    const fav = chrome.runtime.getURL(`/_favicon/?pageUrl=${encodeURIComponent("https://" + domain)}&size=64`);
    return `<div class="ico ico-img" style="background:#fff" data-letter="${letter}" data-color="${color}"><img src="${esc(fav)}" alt="" /></div>`;
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
let currentTabId = null;
let currentServer = "";
let vaultState = null;

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
    : filtered.filter((it) => it.type === "login" && matchesSite(it.url || it.title, currentHost));
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

function letterFallback(img) {
  const tile = img.parentElement;
  tile.textContent = tile.dataset.letter || "?";
  tile.style.background = tile.dataset.color || "#232838"; // restore the letter-tile color
  tile.classList.remove("ico-img");
}

// Wire favicon fallbacks (CSP-safe, no inline onerror): fall back to the letter
// tile on a load error, OR when the provider returns its tiny generic globe
// (≤16px) for a domain it doesn't actually know.
function wireFavicons(root) {
  root.querySelectorAll(".ico[data-letter] img").forEach((img) => {
    img.addEventListener("error", () => letterFallback(img));
    img.addEventListener("load", () => {
      if (img.naturalWidth && img.naturalWidth <= 16) letterFallback(img);
    });
  });
}

function wireRows() {
  wireFavicons(document);
  document.querySelectorAll(".iconbtn[data-act]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const act = btn.dataset.act;
      const item = allItems.find((i) => i.id === id);
      const relocked = (r) => {
        if (r.locked || r.error === "locked") {
          showUnlock({ server: currentServer });
          return true;
        }
        return false;
      };
      if (act === "user") {
        copyText(item.username, "Username");
        return flashCheck(btn);
      }
      if (act === "pass") {
        const r = await send({ type: "REVEAL", id, field: "password" });
        if (relocked(r)) return;
        if (r.ok) { copyText(r.value, "Password"); flashCheck(btn); } else toast(r.error || "Error");
        return;
      }
      if (act === "card") {
        const r = await send({ type: "REVEAL", id, field: "cardNumber" });
        if (relocked(r)) return;
        if (r.ok) { copyText(r.value, "Card number"); flashCheck(btn); } else toast(r.error || "Error");
        return;
      }
      if (act === "fill") {
        const r = await send({ type: "FILL", id, tabId: currentTabId });
        if (relocked(r)) return;
        if (r.ok && r.filled) window.close();
        else toast(r.ok ? "No login field found on this page" : r.error || "Error");
      }
    });
  });
  // Clicking the row itself (not an action button) opens the detail view.
  document.querySelectorAll(".row[data-id]").forEach((row) => {
    row.addEventListener("click", () => showDetail(row.dataset.id));
  });
}

async function showVault(state) {
  vaultState = state;
  currentServer = state.server || currentServer;
  const initial = esc((state.email || "?")[0].toUpperCase());
  app.innerHTML = `
    <div class="hdr">${SHIELD}<h1>Bastion</h1><div class="acct" title="${esc(state.email || "")}">${initial}</div></div>
    <div class="search-wrap"><div class="search">${ICON.search}<input id="q" placeholder="Search ${state.count} items" autofocus /></div></div>
    <div class="scroll"></div>
    <div class="bar">
      <button class="iconbtn" id="settings" title="Settings">${ICON.gear}</button>
      <button class="iconbtn" id="gen" title="Password generator">${ICON.key}</button>
      <button class="iconbtn" id="send" title="Bastion Send">${ICON.send}</button>
      <div class="spacer"></div>
      <button class="iconbtn" id="revoke" title="Sign out everywhere">${ICON.shield}</button>
      <button class="iconbtn" id="lock" title="Lock vault">${ICON.lock}</button>
    </div>`;

  document.getElementById("lock").addEventListener("click", async () => {
    await send({ type: "LOCK" });
    showUnlock({ server: state.server });
  });
  document.getElementById("revoke").addEventListener("click", async () => {
    if (!window.confirm("Revoke every active Bastion session for this account?")) return;
    const result = await send({ type: "REVOKE_ALL" });
    if (result.ok) showUnlock({ server: state.server });
    else toast(result.error || "Could not revoke sessions");
  });
  document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  document.getElementById("gen").addEventListener("click", () => showGenerator());
  document.getElementById("send").addEventListener("click", () => showSend());
  document.getElementById("q").addEventListener("input", (e) => renderVault(e.target.value));

  // current tab host (activeTab grants the URL while the popup is open)
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    currentTabId = tab?.id ?? null;
    currentHost = domainOf(tab?.url || "");
  } catch {
    currentTabId = null;
    currentHost = null;
  }

  const list = await send({ type: "LIST" });
  if (!list.ok) return showUnlock({ server: state.server });
  allItems = list.items;
  renderVault();
}

function showGenerator() {
  const opts = { length: 20, lower: true, upper: true, digits: true, symbols: true };
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><div class="spacer"></div></div>
      <div class="dhero" style="padding-bottom:8px">${SHIELD}<h2>Password generator</h2></div>
      <div class="dscroll">
        <div class="genbox">
          <span class="genpw mono" id="pw"></span>
          <button class="iconbtn" id="regen" title="Regenerate">${ICON.regen}</button>
          <button class="iconbtn" id="copy" title="Copy">${ICON.copy}</button>
        </div>
        <div class="dfield">
          <div class="dlabel">Length: <b id="lenval">${opts.length}</b></div>
          <input type="range" id="len" min="8" max="64" value="${opts.length}" class="range" />
        </div>
        <label class="opt"><input type="checkbox" id="upper" checked /> Uppercase (A–Z)</label>
        <label class="opt"><input type="checkbox" id="lower" checked /> Lowercase (a–z)</label>
        <label class="opt"><input type="checkbox" id="digits" checked /> Digits (2–9)</label>
        <label class="opt"><input type="checkbox" id="symbols" checked /> Symbols (!@#…)</label>
      </div>
    </div>`;

  const pwEl = document.getElementById("pw");
  const regen = () => {
    opts.length = Number(document.getElementById("len").value);
    opts.upper = document.getElementById("upper").checked;
    opts.lower = document.getElementById("lower").checked;
    opts.digits = document.getElementById("digits").checked;
    opts.symbols = document.getElementById("symbols").checked;
    document.getElementById("lenval").textContent = String(opts.length);
    pwEl.textContent = generatePassword(opts);
  };
  regen();

  document.getElementById("back").addEventListener("click", () => showVault(vaultState));
  document.getElementById("regen").addEventListener("click", regen);
  document.getElementById("copy").addEventListener("click", () => copyText(pwEl.textContent, "Password"));
  document.getElementById("len").addEventListener("input", regen);
  ["upper", "lower", "digits", "symbols"].forEach((id) =>
    document.getElementById(id).addEventListener("change", regen)
  );
}

// ── Bastion Send ──
async function showSend() {
  const st = await send({ type: "SEND_STATE" });
  if (!st.ok || st.locked) return showUnlock({ server: currentServer });
  app.innerHTML = `
    <div class="detail">
      <div class="dtop">
        <button class="iconbtn" id="back" title="Back">${ICON.back}</button>
        <b style="flex:1;text-align:center;font-size:15px">Bastion Send</b>
        <span style="width:30px"></span>
      </div>
      <div class="dscroll" id="send-body"></div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showVault(vaultState));
  const body = document.getElementById("send-body");
  if (st.enabled) renderSendHome(body, st.bastionId);
  else renderEnableSend(body);
}

function renderEnableSend(body) {
  body.innerHTML = `
    <div class="send-hero">${SHIELD}<h2>Encrypted notes</h2>
      <p class="sub">Send end-to-end encrypted notes to other Bastion users.
      Only your chosen recipient can open them — the server only ever stores
      ciphertext.</p>
    </div>
    <button class="btn btn-primary btn-block" id="enable">Enable Send</button>
    <div id="enable-msg" style="margin-top:10px"></div>`;
  const btn = document.getElementById("enable");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.textContent = "Enabling…";
    const r = await send({ type: "SEND_ENABLE" });
    if (r.ok) return renderSendHome(body, r.bastionId);
    document.getElementById("enable-msg").innerHTML = `<div class="callout">${esc(r.error || "Could not enable Send.")}</div>`;
    btn.disabled = false;
    btn.textContent = "Enable Send";
  });
}

function renderSendHome(body, bastionId) {
  // Self-heal: Send is enabled locally but the address isn't published yet
  // (e.g. an earlier publish failed). Offer to publish.
  if (!bastionId) {
    body.innerHTML = `
      <div class="send-hero">${SHIELD}<h2>Almost there</h2>
        <p class="sub">Send is enabled on this device, but your Bastion address
        isn't published yet. Make sure your server is running, then publish.</p>
      </div>
      <button class="btn btn-primary btn-block" id="pub">Publish my address</button>
      <div id="enable-msg" style="margin-top:10px"></div>`;
    const btn = document.getElementById("pub");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Publishing…";
      const r = await send({ type: "SEND_ENABLE" });
      if (r.ok && r.bastionId) return renderSendHome(body, r.bastionId);
      document.getElementById("enable-msg").innerHTML = `<div class="callout">${esc(r.error || "Could not publish your address.")}</div>`;
      btn.disabled = false;
      btn.textContent = "Publish my address";
    });
    return;
  }
  body.innerHTML = `
    <div class="dlabel" style="margin-top:10px">Your Bastion address</div>
    <div class="idcard">
      <span class="idtext mono">${esc(bastionId)}</span>
      <button class="iconbtn" id="copyid" title="Copy address">${ICON.copy}</button>
    </div>
    <p class="sub">Share this address so other Bastion users can send you
    encrypted notes.</p>
    <button class="btn btn-block" id="inbox" style="margin-top:8px;display:flex;gap:10px;justify-content:flex-start">${ICON.inbox} Inbox</button>
    <button class="btn btn-primary btn-block" id="compose" style="margin-top:6px;display:flex;gap:10px">${ICON.send} Compose note</button>
    <button class="btn btn-block" id="contacts" style="margin-top:6px;display:flex;gap:10px;justify-content:flex-start">${ICON.contacts} Contacts</button>`;
  const c = document.getElementById("copyid");
  c?.addEventListener("click", () => {
    copyText(bastionId, "Bastion address");
    flashCheck(c);
  });
  document.getElementById("inbox").addEventListener("click", () => showInbox());
  document.getElementById("compose").addEventListener("click", () => showCompose());
  document.getElementById("contacts").addEventListener("click", () => showContacts());
}

// ── inbox ──
function senderChip(m) {
  if (m.keyChanged) return `<span class="badge danger">Key changed</span>`;
  const st = m.sender?.state;
  if (st === "verified") return `<span class="badge ok">${ICON.shield} Verified</span>`;
  if (st === "anonymous") return `<span class="badge">Anonymous</span>`;
  return `<span class="badge warn">Unverified</span>`;
}

function senderName(m) {
  if (m.sender?.state === "anonymous") return "Anonymous sender";
  return m.display || m.sender?.id || "Unknown sender";
}

function fmtTime(sec) {
  if (!sec) return "";
  const d = new Date(sec * 1000);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

async function showInbox() {
  const r = await send({ type: "SEND_INBOX" });
  if (!r.ok || r.locked) {
    if (r.locked) return showUnlock({ server: currentServer });
  }
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Inbox</b><span style="width:30px"></span></div>
      <div class="dscroll" id="inbox-body"></div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showSend());
  const body = document.getElementById("inbox-body");
  if (!r.ok) {
    body.innerHTML = `<div class="callout">${esc(r.error || "Could not load inbox.")}</div>`;
    return;
  }
  const msgs = r.messages || [];
  if (!msgs.length) {
    body.innerHTML = `<div class="empty">No messages.</div>`;
    return;
  }
  body.innerHTML = msgs
    .map((m, i) => {
      const name = m.locked ? esc(m.display || m.contactId) : esc(senderName(m));
      const sub = m.locked
        ? m.pending
          ? "Locked — secure to read"
          : "Locked — enter phrase"
        : m.needsPass
          ? "Passphrase required"
          : esc((m.plaintext || "").slice(0, 60));
      const chip = m.locked ? `<span class="badge">${ICON.lockmini} Locked</span>` : senderChip(m);
      const icon = m.locked || m.needsPass ? ICON.lockmini + " " : "";
      return `<div class="msgrow" data-i="${i}">
        <div class="meta"><div class="t">${icon}${name}</div><div class="s">${sub}</div></div>
        <div class="right">${chip}<div class="time">${esc(fmtTime(m.created_at))}</div></div>
      </div>`;
    })
    .join("");
  body.querySelectorAll(".msgrow").forEach((row) => {
    row.addEventListener("click", () => showMessage(msgs[Number(row.dataset.i)]));
  });
}

function noteBanner(data) {
  return data.keyChanged
    ? `<div class="trust danger">This contact's key changed since you verified them. Don't trust this message — re-verify them.</div>`
    : data.sender?.state === "verified"
      ? `<div class="trust ok">${ICON.shield} Verified — from ${esc(data.display || data.sender.id)}</div>`
      : data.sender?.state === "anonymous"
        ? `<div class="trust">Anonymous sender — Bastion can't tell you who sent this.</div>`
        : `<div class="trust warn">Unverified sender${data.sender?.id ? " · " + esc(data.sender.id) : ""}. Add &amp; verify them to confirm their identity.</div>`;
}

// Render a decrypted note. `del` is the message to delete it; `replyId` enables Reply.
function renderOpenedNote(data, del, replyId) {
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Message</b><button class="iconbtn" id="del" title="Delete">${ICON.trash}</button></div>
      <div class="dscroll" id="msg-body"></div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showInbox());
  document.getElementById("del").addEventListener("click", async () => {
    await send(del);
    toast("Message deleted");
    showInbox();
  });
  document.getElementById("msg-body").innerHTML = `
    ${noteBanner(data)}
    <div class="notebody">${esc(data.plaintext || "")}</div>
    ${replyId ? `<button class="btn btn-block" id="reply" style="margin-top:10px;display:flex;gap:10px;justify-content:center">${ICON.send} Reply</button>` : ""}`;
  if (replyId) document.getElementById("reply").addEventListener("click", () => showCompose(replyId));
}

// ── lock phrase strength (offline-attacker estimate, NOT the WASM open cost) ──
function phraseStrength(p) {
  if (!p) return { label: "", cls: "", pct: 0 };
  let charset = 0;
  if (/[a-z]/.test(p)) charset += 26;
  if (/[A-Z]/.test(p)) charset += 26;
  if (/[0-9]/.test(p)) charset += 10;
  if (/[^a-zA-Z0-9]/.test(p)) charset += 30;
  const bits = p.length * Math.log2(charset || 1);
  if (bits < 40) return { label: "Very weak — minutes–hours if your vault is stolen", cls: "danger", pct: 25 };
  if (bits < 55) return { label: "Weak — days to weeks", cls: "warn", pct: 50 };
  if (bits < 75) return { label: "OK — years", cls: "ok", pct: 75 };
  return { label: "Strong — infeasible offline", cls: "ok", pct: 100 };
}
function updateMeter(p) {
  const el = document.getElementById("meter");
  if (!el) return;
  const s = phraseStrength(p);
  el.innerHTML = p
    ? `<div class="meter-bar"><span class="${s.cls}" style="width:${s.pct}%"></span></div><div class="meter-label ${s.cls}">${esc(s.label)}</div>`
    : "";
}
function lockPhraseError(phrase, confirm) {
  if (phrase.length < 8) return "Use at least 8 characters.";
  if (phrase !== confirm) return "The two phrases don't match.";
  return null;
}

function showMessage(m) {
  if (m.locked && m.pending) return showLockSecure(m); // a lock-contact message not yet secured
  if (m.locked) return showLockedOpen(m); // an already-locked vault record

  // ── normal message ──
  const render = (data) => {
    if (data.needsPass) {
      app.innerHTML = `
        <div class="detail">
          <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Message</b><span style="width:30px"></span></div>
          <div class="dscroll" id="msg-body"></div>
        </div>`;
      document.getElementById("back").addEventListener("click", () => showInbox());
      document.getElementById("msg-body").innerHTML = `
        <div class="trust">${ICON.lockmini} This note is protected by an extra passphrase.</div>
        <div class="field" style="margin-top:8px"><label>Passphrase</label><input class="input" id="mp" type="password" autofocus /></div>
        <div id="mp-msg"></div>
        <button class="btn btn-primary btn-block" id="open">Open</button>`;
      const btn = document.getElementById("open");
      const go = async () => {
        const passphrase = document.getElementById("mp").value;
        btn.disabled = true;
        btn.textContent = "Opening…";
        const rr = await send({ type: "SEND_OPEN", messageId: m.message_id, passphrase });
        // Opening revealed a lock contact → never show plaintext; secure it.
        if (rr.ok && rr.locked) return showLockSecure({ message_id: rr.message_id, contactId: rr.contactId, display: rr.display }, passphrase);
        if (rr.ok) return render(rr);
        document.getElementById("mp-msg").innerHTML = `<div class="callout">${esc(rr.error || "Could not open.")}</div>`;
        btn.disabled = false;
        btn.textContent = "Open";
      };
      btn.addEventListener("click", go);
      document.getElementById("mp").addEventListener("keydown", (e) => e.key === "Enter" && go());
      return;
    }
    renderOpenedNote(data, { type: "SEND_INBOX_DELETE", messageId: m.message_id }, data.sender?.id || null);
  };
  render(m);
}

function showLockSecure(m, sendPassphrase) {
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Secure message</b><span style="width:30px"></span></div>
      <div class="dscroll">
        <div class="trust">${ICON.lockmini} From ${esc(m.display || m.contactId)} — locked. Choose a lock phrase to secure &amp; read it. You'll re-enter the same phrase to open future messages from them.</div>
        <div class="field" style="margin-top:8px"><label>Lock phrase (8+ chars)</label><input class="input" id="p1" type="password" autofocus /></div>
        <div id="meter" class="meter"></div>
        <div class="field"><label>Confirm</label><input class="input" id="p2" type="password" /></div>
        <div id="ls-msg"></div>
        <button class="btn btn-primary btn-block" id="go">Secure &amp; read</button>
      </div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showInbox());
  const p1 = document.getElementById("p1");
  p1.addEventListener("input", () => updateMeter(p1.value));
  document.getElementById("go").addEventListener("click", async (e) => {
    const phrase = p1.value;
    const err = lockPhraseError(phrase, document.getElementById("p2").value);
    if (err) {
      document.getElementById("ls-msg").innerHTML = `<div class="callout">${esc(err)}</div>`;
      return;
    }
    const btn = e.currentTarget;
    btn.disabled = true;
    btn.textContent = "Securing…";
    const rr = await send({ type: "SEND_LOCK_FINALIZE", messageId: m.message_id, contactId: m.contactId, phrase, passphrase: sendPassphrase });
    if (rr.ok) return renderOpenedNote(rr, { type: "SEND_LOCK_DELETE", localId: rr.local_id }, rr.sender?.id || null);
    document.getElementById("ls-msg").innerHTML = `<div class="callout">${esc(rr.error || "Could not secure.")}</div>`;
    btn.disabled = false;
    btn.textContent = "Secure & read";
  });
}

function showLockedOpen(m) {
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Locked message</b><button class="iconbtn" id="del" title="Delete">${ICON.trash}</button></div>
      <div class="dscroll">
        <div class="trust">${ICON.lockmini} From ${esc(m.display || m.contactId)} — enter the lock phrase to read.</div>
        <div class="field" style="margin-top:8px"><label>Lock phrase</label><input class="input" id="p" type="password" autofocus /></div>
        <div id="lo-msg"></div>
        <button class="btn btn-primary btn-block" id="go">Open</button>
      </div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showInbox());
  document.getElementById("del").addEventListener("click", async () => {
    await send({ type: "SEND_LOCK_DELETE", localId: m.local_id });
    toast("Message deleted");
    showInbox();
  });
  const go = async () => {
    const btn = document.getElementById("go");
    btn.disabled = true;
    btn.textContent = "Opening…";
    const rr = await send({ type: "SEND_LOCK_OPEN", localId: m.local_id, phrase: document.getElementById("p").value });
    if (rr.ok) return renderOpenedNote(rr, { type: "SEND_LOCK_DELETE", localId: m.local_id }, rr.sender?.id || null);
    document.getElementById("lo-msg").innerHTML = `<div class="callout">${esc(rr.error || "Wrong lock phrase.")}</div>`;
    btn.disabled = false;
    btn.textContent = "Open";
  };
  document.getElementById("go").addEventListener("click", go);
  document.getElementById("p").addEventListener("keydown", (e) => e.key === "Enter" && go());
}

// ── compose ──
async function showCompose(preselectId) {
  const r = await send({ type: "CONTACTS_LIST" });
  if (!r.ok || r.locked) return showUnlock({ server: currentServer });
  const contacts = r.contacts || [];
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Compose</b><span style="width:30px"></span></div>
      <div class="dscroll" id="compose-body"></div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showSend());
  const body = document.getElementById("compose-body");
  if (!contacts.length) {
    body.innerHTML = `<div class="empty">Add a contact first.</div>
      <button class="btn btn-primary btn-block" id="toc">Go to Contacts</button>`;
    document.getElementById("toc").addEventListener("click", () => showContacts());
    return;
  }
  const opts = contacts
    .map((c) => `<option value="${esc(c.bastion_id)}"${c.bastion_id === preselectId ? " selected" : ""}>${esc(c.display)}${c.verified ? " ✓" : " (unverified)"}</option>`)
    .join("");
  body.innerHTML = `
    <div class="field"><label>To</label><select class="input" id="to">${opts}</select></div>
    <div class="field"><label>Note</label><textarea class="input" id="note" rows="5" placeholder="Your encrypted note…" autofocus></textarea></div>
    <label class="opt"><input type="checkbox" id="signed" checked /> Sign it (the recipient can verify it's from you)</label>
    <div class="field" style="margin-top:8px"><label>Extra passphrase (optional)</label><input class="input" id="pass" type="password" placeholder="shared out-of-band" /></div>
    <div class="field"><label>Expires</label>
      <select class="input" id="exp">
        <option value="0">Never</option>
        <option value="3600">1 hour</option>
        <option value="86400">1 day</option>
        <option value="604800">7 days</option>
      </select>
    </div>
    <div id="send-msg"></div>
    <button class="btn btn-primary btn-block" id="dosend">Send encrypted note</button>`;
  const btn = document.getElementById("dosend");
  btn.addEventListener("click", async () => {
    const recipientId = document.getElementById("to").value;
    const plaintext = document.getElementById("note").value;
    const signed = document.getElementById("signed").checked;
    const pass = document.getElementById("pass").value;
    const expSec = Number(document.getElementById("exp").value);
    if (!plaintext.trim()) {
      document.getElementById("send-msg").innerHTML = `<div class="callout">Write a note first.</div>`;
      return;
    }
    btn.disabled = true;
    btn.textContent = "Sending…";
    const expiresAt = expSec ? Math.floor(Date.now() / 1000) + expSec : null;
    const rr = await send({ type: "SEND_COMPOSE", recipientId, plaintext, passphrase: pass || undefined, signed, expiresAt });
    if (rr.ok) {
      toast("Note sent");
      return showSend();
    }
    const msg = rr.keyChanged
      ? "This contact's key changed — re-verify them before sending."
      : rr.error || "Could not send.";
    document.getElementById("send-msg").innerHTML = `<div class="callout">${esc(msg)}</div>`;
    btn.disabled = false;
    btn.textContent = "Send encrypted note";
  });
}

// ── contacts ──
function trustBadge(c) {
  return c.verified
    ? `<span class="badge ok">${ICON.shield} Verified</span>`
    : `<span class="badge warn">Unverified</span>`;
}

function contactRow(c) {
  return `<div class="contact" data-id="${esc(c.bastion_id)}">
    <div class="ico" style="background:${colorFor(c.display || c.bastion_id)}">${esc((c.display || "?")[0].toUpperCase())}</div>
    <div class="meta"><div class="t">${esc(c.display)}</div><div class="s mono">${esc(c.bastion_id)}</div></div>
    ${trustBadge(c)}
    <button class="iconbtn${c.lock_enabled ? " on" : ""}" data-lock title="${c.lock_enabled ? "Lock phrase on" : "Enable lock phrase"}">${ICON.lockmini}</button>
    <button class="iconbtn" data-del title="Remove">${ICON.trash}</button>
  </div>`;
}

function showLockEnable(bastionId) {
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Lock phrase</b><span style="width:30px"></span></div>
      <div class="dscroll">
        <div class="warnbox">
          <b>⚠️ Before you enable a lock phrase</b>
          <p>Messages from this contact get locked behind a phrase you choose the first time you secure one.</p>
          <ul>
            <li>The phrase is <b>never stored</b>. Forget it and those messages are <b>permanently unreadable</b> — even by you.</li>
            <li>It <b>can't be changed</b>. To change it, delete &amp; re-add the contact (locked messages are lost).</li>
            <li>A short phrase can be brute-forced if your vault is stolen — use <b>8+ characters</b>, ideally a passphrase. For real secrecy, ask the sender to add a send passphrase.</li>
          </ul>
        </div>
        <button class="btn btn-primary btn-block" id="enable">I understand — enable</button>
        <button class="btn btn-block" id="cancel" style="margin-top:6px">Cancel</button>
      </div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showContacts());
  document.getElementById("cancel").addEventListener("click", () => showContacts());
  document.getElementById("enable").addEventListener("click", async () => {
    const r = await send({ type: "CONTACTS_SET_LOCK", bastionId });
    if (r.ok) {
      toast("Lock phrase enabled");
      showContacts();
    } else toast(r.error || "Could not enable");
  });
}

async function showContacts() {
  const r = await send({ type: "CONTACTS_LIST" });
  if (!r.ok || r.locked) return showUnlock({ server: currentServer });
  const list = r.contacts || [];
  app.innerHTML = `
    <div class="detail">
      <div class="dtop">
        <button class="iconbtn" id="back" title="Back">${ICON.back}</button>
        <b style="flex:1;text-align:center;font-size:15px">Contacts</b>
        <button class="iconbtn" id="add" title="Add contact">${ICON.plus}</button>
      </div>
      <div class="dscroll" id="c-body"></div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showSend());
  document.getElementById("add").addEventListener("click", () => showAddContact());
  const body = document.getElementById("c-body");
  if (!list.length) {
    body.innerHTML = `<div class="empty">No contacts yet.<br/>Add someone by their Bastion address.</div>`;
    return;
  }
  body.innerHTML = list.map(contactRow).join("");
  body.querySelectorAll(".contact[data-id]").forEach((row) => {
    const c = list.find((x) => x.bastion_id === row.dataset.id);
    row.querySelector("[data-lock]")?.addEventListener("click", (e) => {
      e.stopPropagation();
      if (c?.lock_enabled) {
        toast("Lock phrase is on. Delete & re-add the contact to change it.");
        return;
      }
      showLockEnable(row.dataset.id);
    });
    row.querySelector("[data-del]")?.addEventListener("click", async (e) => {
      e.stopPropagation();
      await send({ type: "CONTACTS_DELETE", bastionId: row.dataset.id });
      showContacts();
    });
  });
}

function showAddContact() {
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Add contact</b><span style="width:30px"></span></div>
      <div class="dscroll">
        <div class="field"><label>Bastion address</label><input class="input mono" id="addr" placeholder="XEDU0BHFS74J4XCVVENVE2WGHY" autofocus /></div>
        <div id="add-msg"></div>
        <button class="btn btn-primary btn-block" id="find">Find</button>
      </div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showContacts());
  const find = document.getElementById("find");
  const go = async () => {
    const addr = document.getElementById("addr").value.trim();
    find.disabled = true;
    find.textContent = "Finding…";
    const r = await send({ type: "CONTACTS_RESOLVE", bastionId: addr });
    if (r.ok) return showVerify(r);
    document.getElementById("add-msg").innerHTML = `<div class="callout">${esc(r.error || "Not found.")}</div>`;
    find.disabled = false;
    find.textContent = "Find";
  };
  find.addEventListener("click", go);
  document.getElementById("addr").addEventListener("keydown", (e) => e.key === "Enter" && go());
}

function showVerify(r) {
  const grouped = String(r.safety_number || "").replace(/(\d{5})(?=\d)/g, "$1 ");
  app.innerHTML = `
    <div class="detail">
      <div class="dtop"><button class="iconbtn" id="back" title="Back">${ICON.back}</button><b style="flex:1;text-align:center;font-size:15px">Verify contact</b><span style="width:30px"></span></div>
      <div class="dscroll">
        <div class="field"><label>Name (optional)</label><input class="input" id="name" placeholder="${esc(r.bastionId)}" /></div>
        <div class="dlabel" style="margin-top:8px">Safety number</div>
        <div class="safety mono">${esc(grouped)}</div>
        <p class="sub">Compare these 60 digits with the owner of <span class="mono">${esc(r.bastionId)}</span> over a separate, trusted channel (in person, a call). If they match, the connection is genuinely end-to-end — a malicious server can't impersonate them.</p>
        <button class="btn btn-primary btn-block" id="verify">Numbers match — verify &amp; save</button>
        <button class="btn btn-block" id="saveunv" style="margin-top:6px">Save without verifying</button>
        <div id="v-msg" style="margin-top:8px"></div>
      </div>
    </div>`;
  document.getElementById("back").addEventListener("click", () => showAddContact());
  const save = async (verified) => {
    const display = document.getElementById("name").value.trim();
    const rr = await send({
      type: "CONTACTS_SAVE",
      bastionId: r.bastionId,
      public: r.public,
      pinFp: r.pinFp,
      safety_number: r.safety_number,
      display,
      verified,
    });
    if (rr.ok) return showContacts();
    document.getElementById("v-msg").innerHTML = `<div class="callout">${esc(rr.error || "Could not save.")}</div>`;
  };
  document.getElementById("verify").addEventListener("click", () => save(true));
  document.getElementById("saveunv").addEventListener("click", () => save(false));
}

async function showDetail(id) {
  const r = await send({ type: "ITEM", id });
  if (!r.ok || r.locked) return showUnlock({ server: currentServer });
  const it = r.item;

  const lengths = it.secretLengths || {};
  const mask = (length) => "•".repeat(Math.min(length || 0, 20));

  // A plain field: its value is not secret, so it may live in the DOM.
  const field = (label, value, opts = {}) => {
    if (!value) return "";
    const { mono = false, link = false } = opts;
    const acts =
      `${link ? `<button class="iconbtn" data-open title="Open">${ICON.link}</button>` : ""}` +
      `<button class="iconbtn" data-copy title="Copy ${esc(label)}">${ICON.copy}</button>`;
    return `<div class="dfield">
      <div class="dlabel">${esc(label)}</div>
      <div class="dval">
        <span class="dtext ${mono ? "mono" : ""}" data-value="${esc(value)}" data-shown="0">${esc(value)}</span>
        <div class="dacts">${acts}</div>
      </div>
    </div>`;
  };

  // A secret field: the popup never receives its value. Only the mask width
  // is known here; the plaintext is fetched through REVEAL when the user
  // reveals or copies it, and is never written into the DOM as an attribute.
  const secretField = (label, name, opts = {}) => {
    const length = lengths[name];
    if (!length) return "";
    const { mono = false } = opts;
    const acts =
      `<button class="iconbtn" data-reveal title="Reveal">${ICON.eye}</button>` +
      `<button class="iconbtn" data-copy title="Copy ${esc(label)}">${ICON.copy}</button>`;
    return `<div class="dfield" data-field="${esc(name)}">
      <div class="dlabel">${esc(label)}</div>
      <div class="dval">
        <span class="dtext ${mono ? "mono" : ""}" data-shown="0">${mask(length)}</span>
        <div class="dacts">${acts}</div>
      </div>
    </div>`;
  };

  let body = "";
  if (it.type === "login") {
    const s = it.passwordHealth || { label: "No password", ok: false };
    body =
      field("Email or Username", it.username) +
      secretField("Password", "password", { mono: true }) +
      (lengths.password
        ? `<div class="dfield"><div class="dlabel">Password Health</div>
             <div class="health ${s.ok ? "ok" : "warn"}">${ICON.shield}<span>${esc(s.label)}</span></div></div>`
        : "") +
      field("Website", it.url, { link: true });
  } else if (it.type === "card") {
    body =
      field("Cardholder", it.username) +
      secretField("Card Number", "cardNumber", { mono: true }) +
      field("Expiry", it.cardExp, { mono: true }) +
      secretField("CVV", "cardCvv", { mono: true });
  }
  body += field("Notes", it.notes);

  app.innerHTML = `
    <div class="detail">
      <div class="dtop">
        <button class="iconbtn" id="back" title="Back">${ICON.back}</button>
        <div class="spacer"></div>
      </div>
      <div class="dhero">${avatarFor(toMetaLike(it))}<h2>${esc(it.title)}</h2></div>
      <div class="dscroll">${body || `<div class="empty">Nothing to show.</div>`}</div>
    </div>`;

  document.getElementById("back").addEventListener("click", () => showVault(vaultState));

  wireFavicons(app); // same favicon fallback as the list

  // Fetches one secret field on demand. The value stays in this closure for
  // the duration of the call and is never stored on the element.
  const readSecret = async (name) => {
    const r = await send({ type: "REVEAL", id, field: name });
    if (!r.ok) {
      toast(r.locked ? "Vault locked" : "Could not read the field");
      return null;
    }
    return r.value || "";
  };

  app.querySelectorAll(".dfield").forEach((f) => {
    const text = f.querySelector(".dtext");
    const name = f.dataset.field || null; // set only on secret fields
    const value = text?.dataset.value || "";
    const copyBtn = f.querySelector("[data-copy]");
    copyBtn?.addEventListener("click", async () => {
      const plaintext = name ? await readSecret(name) : value;
      if (plaintext === null) return;
      copyText(plaintext, f.querySelector(".dlabel").textContent);
      flashCheck(copyBtn);
    });
    f.querySelector("[data-open]")?.addEventListener("click", () => {
      const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
      chrome.tabs.create({ url });
    });
    const reveal = f.querySelector("[data-reveal]");
    reveal?.addEventListener("click", async () => {
      const shown = text.dataset.shown === "1";
      if (shown) {
        // Re-mask from the length alone: nothing revealed is kept around.
        text.dataset.shown = "0";
        text.textContent = mask(lengths[name]);
        reveal.innerHTML = ICON.eye;
        return;
      }
      const plaintext = await readSecret(name);
      if (plaintext === null) return;
      text.dataset.shown = "1";
      text.textContent = plaintext;
      reveal.innerHTML = ICON.eyeOff;
    });
  });
}

// Minimal shape for avatarFor() from a full item.
function toMetaLike(it) {
  return {
    type: it.type,
    title: it.title,
    url: it.url,
    cardBankDomain: it.cardBankDomain,
  };
}

function showUnlock(state) {
  currentServer = state.server || currentServer;
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
