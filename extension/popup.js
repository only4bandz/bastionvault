// Bastion popup — a thin view over the background service worker. It never
// runs crypto or holds the vault key; it asks the worker for item metadata and
// for a single secret only at the moment the user copies or fills it.

import { domainOf, matchesSite } from "./lib/match.js";
import { generatePassword } from "./lib/generator.js";

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
  back: '<svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 6-6 6 6 6"/></svg>',
  eye: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeOff: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 3l18 18"/><path d="M10.6 10.6a3 3 0 0 0 4.2 4.2"/><path d="M9.4 5.2A10 10 0 0 1 22 12a13 13 0 0 1-2.4 3.2M6.3 6.3A13 13 0 0 0 2 12s3.5 7 10 7a10 10 0 0 0 3-.5"/></svg>',
  link: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 11a5 5 0 0 0-7 0l-3 3a5 5 0 0 0 7 7l1-1"/><path d="M10 13a5 5 0 0 0 7 0l3-3a5 5 0 0 0-7-7l-1 1"/></svg>',
  shield: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 3v5c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-3z"/><path d="m9 12 2 2 4-4"/></svg>',
  regen: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/><path d="M3 21v-5h5"/></svg>',
  key: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="15" r="4"/><path d="m10.85 12.15 8.15-8.15"/><path d="m18 5 2 2"/><path d="m15 8 2 2"/></svg>',
};
const SHIELD = '<svg class="logo" viewBox="0 0 32 32" aria-hidden><defs><linearGradient id="bg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#9a8cff"/><stop offset="1" stop-color="#5a47e6"/></linearGradient></defs><path fill="url(#bg)" d="M16 2l11 4v8.5c0 7-4.7 12.9-11 15.5C9.7 27.4 5 21.5 5 14.5V6l11-4z"/><circle cx="16" cy="14.5" r="3" fill="#0a0c12"/><path fill="#0a0c12" d="M14.6 15.5h2.8l1 5.5h-4.8z"/></svg>';

function avatarFor(it) {
  const domain = it.type === "card" ? it.cardBankDomain : domainOf(it.url || it.title);
  const letter = esc((it.title || "?")[0].toUpperCase());
  const color = colorFor(it.title || "");
  if (domain) {
    // Real favicons sit on a clean white tile (like NordPass) so transparent
    // logos don't bleed our accent color. The <img> error fallback is wired in
    // JS (wireRows) — inline onerror= is forbidden by the extension-page CSP.
    // We stash the fallback color on the tile so wireRows can restore it.
    // High-res favicon (sz=128) so it stays crisp even in the 64px detail
    // hero. Resolved by the browser, never by the Bastion server.
    return `<div class="ico ico-img" style="background:#fff" data-letter="${letter}" data-color="${color}"><img src="https://www.google.com/s2/favicons?sz=128&domain=${esc(domain)}" alt="" /></div>`;
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
let currentServer = "";
let vaultState = null;

// Rough local password-strength estimate (no network). Returns {label, ok}.
function passwordStrength(pw) {
  if (!pw) return { label: "No password", ok: false, level: 0 };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 12) score++;
  if (pw.length >= 16) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  if (score >= 5) return { label: "Strong password", ok: true, level: 3 };
  if (score >= 3) return { label: "Fair password", ok: false, level: 2 };
  return { label: "Weak password", ok: false, level: 1 };
}

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
      if (act === "user") return copyText(item.username, "Username");
      if (act === "pass") {
        const r = await send({ type: "REVEAL", id, field: "password" });
        if (relocked(r)) return;
        return r.ok ? copyText(r.value, "Password") : toast(r.error || "Error");
      }
      if (act === "card") {
        const r = await send({ type: "REVEAL", id, field: "cardNumber" });
        if (relocked(r)) return;
        return r.ok ? copyText(r.value, "Card number") : toast(r.error || "Error");
      }
      if (act === "fill") {
        const r = await send({ type: "FILL", id });
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
      <div class="spacer"></div>
      <button class="iconbtn" id="lock" title="Lock vault">${ICON.lock}</button>
    </div>`;

  document.getElementById("lock").addEventListener("click", async () => {
    await send({ type: "LOCK" });
    showUnlock({ server: state.server });
  });
  document.getElementById("settings").addEventListener("click", () => chrome.runtime.openOptionsPage());
  document.getElementById("gen").addEventListener("click", () => showGenerator());
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

async function showDetail(id) {
  const r = await send({ type: "ITEM", id });
  if (!r.ok || r.locked) return showUnlock({ server: currentServer });
  const it = r.item;

  // One field block. `secret` masks the value behind a reveal toggle.
  const field = (label, value, opts = {}) => {
    if (!value) return "";
    const { secret = false, mono = false, link = false } = opts;
    const display = secret ? "•".repeat(Math.min(value.length, 20)) : value;
    const acts =
      `${link ? `<button class="iconbtn" data-open title="Open">${ICON.link}</button>` : ""}` +
      `${secret ? `<button class="iconbtn" data-reveal title="Reveal">${ICON.eye}</button>` : ""}` +
      `<button class="iconbtn" data-copy title="Copy ${esc(label)}">${ICON.copy}</button>`;
    return `<div class="dfield">
      <div class="dlabel">${esc(label)}</div>
      <div class="dval">
        <span class="dtext ${mono ? "mono" : ""}" data-value="${esc(value)}" data-secret="${secret ? 1 : 0}" data-shown="0">${esc(display)}</span>
        <div class="dacts">${acts}</div>
      </div>
    </div>`;
  };

  let body = "";
  if (it.type === "login") {
    const s = passwordStrength(it.password || "");
    body =
      field("Email or Username", it.username) +
      field("Password", it.password, { secret: true, mono: true }) +
      (it.password
        ? `<div class="dfield"><div class="dlabel">Password Health</div>
             <div class="health ${s.ok ? "ok" : "warn"}">${ICON.shield}<span>${esc(s.label)}</span></div></div>`
        : "") +
      field("Website", it.url, { link: true });
  } else if (it.type === "card") {
    body =
      field("Cardholder", it.username) +
      field("Card Number", it.cardNumber, { secret: true, mono: true }) +
      field("Expiry", it.cardExp, { mono: true }) +
      field("CVV", it.cardCvv, { secret: true, mono: true });
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

  app.querySelectorAll(".dfield").forEach((f) => {
    const text = f.querySelector(".dtext");
    const value = text?.dataset.value || "";
    f.querySelector("[data-copy]")?.addEventListener("click", () =>
      copyText(value, f.querySelector(".dlabel").textContent)
    );
    f.querySelector("[data-open]")?.addEventListener("click", () => {
      const url = /^https?:\/\//i.test(value) ? value : `https://${value}`;
      chrome.tabs.create({ url });
    });
    const reveal = f.querySelector("[data-reveal]");
    reveal?.addEventListener("click", () => {
      const shown = text.dataset.shown === "1";
      text.dataset.shown = shown ? "0" : "1";
      text.textContent = shown ? "•".repeat(Math.min(value.length, 20)) : value;
      reveal.innerHTML = shown ? ICON.eye : ICON.eyeOff;
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
