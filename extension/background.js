// Bastion extension — background service worker (ES module).
//
// This is the ONLY place the vault is ever decrypted. It holds the unlocked
// session — the WASM `Account` (which owns the vault key), the bearer token and
// the decrypted items — in memory ONLY. Nothing secret is written to
// chrome.storage / disk (anti-stealer model, mirrors crypto-wasm Account::lock).
// When Chrome evicts this worker the session is simply lost, which re-locks the
// vault. Auto-lock on inactivity is enforced with a chrome.alarms timer.
//
// The popup and options pages are thin views that talk to this worker via
// chrome.runtime messages; they never run the crypto themselves.

import init, { unlock } from "./pkg/crypto_wasm.js";
import { makeApi, ApiError } from "./lib/api.js";

const DEFAULT_SERVER = "http://127.0.0.1:7777";
const AUTO_LOCK_MINUTES = 10;
const AUTOLOCK_ALARM = "bastion-autolock";

// ── WASM (loaded lazily, once per worker lifetime) ──
let wasmReady = null;
function ensureWasm() {
  if (!wasmReady) wasmReady = init();
  return wasmReady;
}

// ── in-memory session (never persisted) ──
// { account, token, email, server, items: Map<id, item> }
let session = null;

async function getServerUrl() {
  const { serverUrl } = await chrome.storage.local.get("serverUrl");
  return serverUrl || DEFAULT_SERVER;
}

function bumpAutolock() {
  chrome.alarms.create(AUTOLOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
}

function lock() {
  if (session) {
    const { account, token, server } = session;
    if (token) makeApi(server).logout(token).catch(() => {});
    try {
      account.lock(); // drops + zeroizes the vault key inside WASM
    } catch {
      /* already locked */
    }
  }
  session = null;
  chrome.alarms.clear(AUTOLOCK_ALARM);
  chrome.action.setBadgeText({ text: "" });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) lock();
});

// Lock as soon as the browser locks / the user signs out of the OS session.
if (chrome.idle?.onStateChanged) {
  chrome.idle.onStateChanged.addListener((state) => {
    if (state === "locked") lock();
  });
}

async function doUnlock(email, password, secretKey) {
  await ensureWasm();
  const server = await getServerUrl();
  const api = makeApi(server);

  let pre;
  try {
    pre = await api.prelogin(email);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) throw new Error("No vault found for this email.");
    throw e;
  }

  // unlock() only needs salt/kdf/wrapped key; the auth secret is re-derived inside.
  const regJson = JSON.stringify({
    version: 1,
    salt: pre.salt,
    kdf: pre.kdf,
    wrapped_vault_key: pre.wrapped_vault_key,
    auth_secret: "",
  });

  let account;
  try {
    account = unlock(password, secretKey, regJson);
  } catch {
    throw new Error("Invalid master password or Secret Key.");
  }

  const token = await api.login(email, account.auth_secret);
  const vault = await api.getVault(token);

  const items = new Map();
  for (const [id, blob] of Object.entries(vault.items || {})) {
    try {
      items.set(id, JSON.parse(account.decrypt_item(JSON.stringify(blob), id)));
    } catch {
      // Skip an item that fails to decrypt (corrupt / tampered).
    }
  }

  session = { account, token, email, server, items };
  bumpAutolock();
  chrome.action.setBadgeText({ text: "✓" });
  chrome.action.setBadgeBackgroundColor({ color: "#5a47e6" });
}

// Public, non-secret view of an item for the popup list.
function toMeta(it) {
  return {
    id: it.id,
    type: it.type,
    title: it.title,
    username: it.username || "",
    url: it.url || "",
    cardBrand: it.cardBrand || "",
    cardBankDomain: it.cardBankDomain || "",
    cardLast4: (it.cardNumber || "").replace(/\D/g, "").slice(-4),
    hasPassword: !!it.password,
    favorite: !!it.favorite,
    updatedAt: it.updatedAt || 0,
  };
}

function sortItems(a, b) {
  if (!!b.favorite !== !!a.favorite) return a.favorite ? -1 : 1;
  return (b.updatedAt || 0) - (a.updatedAt || 0);
}

function requireSession() {
  if (!session) throw new Error("locked");
}

// ── credential autofill (injected into the active tab on demand) ──
async function fillActiveTab(item) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab to fill.");
  // Browser-internal pages (chrome://, the Web Store, etc.) can't be scripted.
  if (!/^https?:\/\//i.test(tab.url || "")) {
    throw new Error("Open a website to fill credentials — this page can't be filled.");
  }
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, allFrames: true },
    args: [{ username: item.username || "", password: item.password || "" }],
    func: injectedFill,
  });
  return results.some((r) => r.result);
}

// Runs in the page context. Must be self-contained (it is serialized, so it
// cannot reference anything outside its own body).
function injectedFill(creds) {
  const setNative = (el, value) => {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, value);
    else el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  };

  const pw = document.querySelector('input[type="password"]:not([disabled]):not([readonly])');
  let user = null;

  if (pw) {
    const scope = pw.form || document;
    const cands = Array.from(scope.querySelectorAll("input")).filter(
      (i) => i !== pw && i.type !== "password" && !i.disabled && !i.readOnly &&
        ["text", "email", "tel", ""].includes((i.type || "").toLowerCase())
    );
    const hint = (i) => `${i.name} ${i.id} ${i.autocomplete}`.toLowerCase();
    user = cands.find((i) => /user|email|login|account|phone/.test(hint(i))) || cands[0] || null;
  } else {
    user = document.querySelector(
      'input[autocomplete="username"], input[type="email"], input[name*="user" i], input[id*="user" i]'
    );
  }

  let filled = false;
  if (pw && creds.password) {
    setNative(pw, creds.password);
    filled = true;
  }
  if (user && creds.username) {
    setNative(user, creds.username);
    filled = true;
  }
  return filled;
}

// ── message router ──
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      switch (msg?.type) {
        case "STATE": {
          if (session) bumpAutolock();
          const server = session?.server || (await getServerUrl());
          sendResponse({
            ok: true,
            locked: !session,
            email: session?.email || null,
            server,
            count: session ? session.items.size : 0,
          });
          break;
        }
        case "UNLOCK":
          await doUnlock(msg.email, msg.password, msg.secretKey);
          sendResponse({ ok: true });
          break;
        case "LOCK":
          lock();
          sendResponse({ ok: true });
          break;
        case "LIST":
          requireSession();
          bumpAutolock();
          sendResponse({ ok: true, items: [...session.items.values()].map(toMeta).sort(sortItems) });
          break;
        case "REVEAL": {
          requireSession();
          bumpAutolock();
          const it = session.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          sendResponse({ ok: true, value: it[msg.field] || "" });
          break;
        }
        case "FILL": {
          requireSession();
          bumpAutolock();
          const it = session.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          const filled = await fillActiveTab(it);
          sendResponse({ ok: true, filled });
          break;
        }
        default:
          sendResponse({ ok: false, error: "Unknown message." });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e), locked: e?.message === "locked" });
    }
  })();
  return true; // keep the channel open for the async response
});
