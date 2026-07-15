// Bastion extension — background service worker (ES module).
//
// This is the ONLY place the vault is ever decrypted. It holds the unlocked
// session — the WASM `Account` (which owns the vault key), the bearer token and
// the decrypted items — in memory.
//
// MV3 evicts this worker after seconds of inactivity, which would wipe that
// memory and force a re-unlock. To honour the user's "keep unlocked for N"
// choice, the session is also mirrored into `chrome.storage.session`: a
// RAM-only, extension-private store that survives worker eviction but is never
// written to disk and is unreadable by page scripts / infostealers. It holds
// the exported vault key (see crypto-wasm Account::export_session) so the
// worker can rehydrate WITHOUT re-deriving Argon2id — never the master password.
// Everything is cleared on lock or at expiry; nothing secret touches any
// disk-backed web storage (enforced by scripts/check-no-browser-secret-storage.sh).

import init, { unlock, rehydrate, send_safety_number, send_lock_open, send_lock_new_params } from "./pkg/crypto_wasm.js";
import { autofillPolicyError } from "./lib/autofill-policy.js";
import { makeApi, ApiError } from "./lib/api.js";
import { matchesSite } from "./lib/match.js";
import { makeStagedUsername, stagedUsernameFor } from "./lib/staged-username.js";
import { loadVaultState, VaultIntegrityError } from "./lib/vault-load.js";
import { DEFAULT_SERVER, normalizeServerUrl } from "./lib/server-url.js";
import { SIGNING_UNAVAILABLE, senderIdForMode } from "./lib/send-policy.js";

const DEFAULT_KEEP_MINUTES = 60;
const AUTOLOCK_ALARM = "bastion-autolock";
const SESSION_KEY = "session"; // key in chrome.storage.session

// Reserved id for the encrypted Send identity (must match crypto-wasm
// send_identity_item_id()).
const SEND_IDENTITY_ID = "bastion:send-identity";
// Reserved id for the encrypted verified-contacts list.
const SEND_CONTACTS_ID = "bastion:send-contacts";
// Reserved prefix for lock-phrase-protected (re-encrypted) messages.
const SEND_LOCKED_PREFIX = "bastion:send-locked:";

// A lock-enabled contact for this sender id (the recipient set a lock phrase).
const lockContactFor = (s, id) => (s.contacts || []).find((c) => c.bastion_id === id && c.lock_enabled);

// Canonical JSON of a PublicIdentity (stable key order) for fingerprinting.
const canonPublic = (pub) => JSON.stringify(pub, Object.keys(pub).sort());
async function sha256hex(str) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Persist the verified-contacts list as the encrypted reserved vault item.
async function saveContacts(s) {
  const blob = JSON.parse(s.account.encrypt_item(JSON.stringify(s.contacts || []), SEND_CONTACTS_ID));
  await makeApi(s.server).putItem(s.token, SEND_CONTACTS_ID, blob);
}

// Open one inbox blob (BR5 two-pass): pass 1 with no verifier discovers the
// sender (the claimed id lives *inside* the ciphertext); for a known VERIFIED
// contact, re-open against the PINNED public to reach "verified" — a signature
// failure there means the key changed since we verified them.
function openMessage(s, blob, passphrase) {
  let r1;
  try {
    r1 = JSON.parse(s.account.send_open(JSON.stringify(blob), passphrase || undefined, undefined));
  } catch {
    return passphrase ? { error: "Wrong passphrase or corrupted message." } : { needsPass: true };
  }
  let sender = r1.sender; // { state, id }
  let keyChanged = false;
  if (sender.state === "unverified" && sender.id) {
    const v = (s.contacts || []).find((c) => c.bastion_id === sender.id && c.verified);
    if (v) {
      try {
        sender = JSON.parse(s.account.send_open(JSON.stringify(blob), passphrase || undefined, JSON.stringify(v.public))).sender;
      } catch {
        keyChanged = true; // signature failed against the pinned key
      }
    }
  }
  const known = (s.contacts || []).find((c) => c.bastion_id === sender.id);
  return { plaintext: r1.plaintext, sender, display: known?.display || null, keyChanged };
}
const PENDING_TTL_MS = 10 * 60 * 1000; // a staged "save?" expires after 10 min

// chrome.storage.session is TRUSTED_CONTEXTS by default (NOT readable by content
// scripts); set it explicitly so a future code change can't silently widen it
// and expose the in-RAM vault key / staged passwords to page-injected scripts.
chrome.storage.session.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});

// Messages a content script (running on arbitrary web pages) is allowed to send.
// Everything else (LIST/ITEM/REVEAL/FILL/UNLOCK/LOCK/STATE) is for extension
// pages only — see the sender check in the message router.
const CONTENT_ALLOWED = new Set(["SUGGEST", "CREDS", "STAGE_USER", "STAGE_SAVE", "PENDING_SAVE", "SAVE_LOGIN", "CLEAR_PENDING"]);
const EXT_ORIGIN = chrome.runtime.getURL("").replace(/\/$/, "");

// Host of the sender frame (for content-script messages); null for ext pages.
function hostFromSender(sender) {
  try {
    return new URL(sender.url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return null;
  }
}

// ── WASM (loaded lazily, once per worker lifetime) ──
let wasmReady = null;
function ensureWasm() {
  if (!wasmReady) wasmReady = init();
  return wasmReady;
}

// ── in-memory session (fast path) ──
// { account, token, email, server, items: Map<id, item> }
let session = null;

async function getServerUrl() {
  const { serverUrl } = await chrome.storage.local.get("serverUrl");
  try {
    return normalizeServerUrl(serverUrl || DEFAULT_SERVER).url;
  } catch {
    return DEFAULT_SERVER;
  }
}

const MAX_KEEP_MINUTES = 12 * 60; // hard ceiling (matches the options UI max)
async function getKeepMinutes() {
  const { keepUnlockMinutes } = await chrome.storage.local.get("keepUnlockMinutes");
  const n = Number(keepUnlockMinutes);
  if (!Number.isFinite(n) || n <= 0) return DEFAULT_KEEP_MINUTES;
  return Math.min(n, MAX_KEEP_MINUTES); // clamp so a tampered storage value can't extend it
}

// Push the lock deadline out to now + keep-unlock window, updating the alarm
// (proactive lock), the persisted session, and the in-memory deadline (so a
// sensitive op never runs past expiry even if the alarm is late).
// IMPORTANT: only call on EXPLICIT user actions (unlock, popup interaction,
// credential pick/fill). Never from passive content-script signals like
// SUGGEST/PENDING_SAVE, or merely browsing pages with login fields would keep
// the vault unlocked indefinitely.
async function touchSession() {
  const minutes = await getKeepMinutes();
  const expiresAt = Date.now() + minutes * 60_000;
  chrome.alarms.create(AUTOLOCK_ALARM, { when: expiresAt });
  if (session) session.expiresAt = expiresAt;
  const stored = await chrome.storage.session.get(SESSION_KEY);
  if (stored[SESSION_KEY]) {
    stored[SESSION_KEY].expiresAt = expiresAt;
    await chrome.storage.session.set({ [SESSION_KEY]: stored[SESSION_KEY] });
  }
  return expiresAt;
}

async function persistSession() {
  if (!session) return;
  const minutes = await getKeepMinutes();
  await chrome.storage.session.set({
    [SESSION_KEY]: {
      crypto: session.account.export_session(), // contains the vault key (RAM only)
      email: session.email,
      server: session.server,
      expiresAt: Date.now() + minutes * 60_000,
    },
  });
}

// ── pending "save this login?" (staged at form submit, survives the navigation
// that follows via storage.session; plaintext lives in RAM only until the user
// saves or dismisses) ──
let pendingSave = null;
let lastUser = null; // origin-bound username for multi-step sign-ups
async function setPending(p) {
  pendingSave = { ...p, stagedAt: Date.now() };
  await chrome.storage.session.set({ pendingSave });
}
async function getPending() {
  if (!pendingSave) pendingSave = (await chrome.storage.session.get("pendingSave")).pendingSave || null;
  // Expire a staged credential so a plaintext password never lingers.
  if (pendingSave && Date.now() - (pendingSave.stagedAt || 0) > PENDING_TTL_MS) {
    await clearPending();
    return null;
  }
  return pendingSave;
}
async function clearPending() {
  pendingSave = null;
  await chrome.storage.session.remove("pendingSave");
}

async function setLastUser(username, host) {
  lastUser = makeStagedUsername(username, host);
  if (lastUser) await chrome.storage.session.set({ lastUser });
  else await chrome.storage.session.remove("lastUser");
}

async function takeLastUser(host) {
  if (!lastUser) lastUser = (await chrome.storage.session.get("lastUser")).lastUser || null;
  const username = stagedUsernameFor(lastUser, host);
  lastUser = null;
  await chrome.storage.session.remove("lastUser");
  return username;
}

async function lock() {
  await clearPending(); // don't leave a staged plaintext password around
  lastUser = null;
  await chrome.storage.session.remove("lastUser");
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
  await chrome.storage.session.remove(SESSION_KEY);
  chrome.alarms.clear(AUTOLOCK_ALARM);
  chrome.action.setBadgeText({ text: "" });
}

// Returns the live session, rehydrating from storage.session if the worker was
// evicted. Returns null (locked) if there is no valid, unexpired session.
async function ensureSession() {
  if (session) {
    if (session.expiresAt && Date.now() > session.expiresAt) {
      await lock(); // enforce expiry on the in-memory path, not just via the alarm
      return null;
    }
    return session;
  }

  const stored = (await chrome.storage.session.get(SESSION_KEY))[SESSION_KEY];
  if (!stored) return null;
  if (Date.now() > stored.expiresAt) {
    await chrome.storage.session.remove(SESSION_KEY);
    return null;
  }

  let server;
  try {
    server = normalizeServerUrl(stored.server).url;
  } catch {
    await chrome.storage.session.remove(SESSION_KEY);
    return null;
  }

  let account;
  let api;
  let token;
  try {
    await ensureWasm();
    account = rehydrate(stored.crypto); // no Argon2id; just the vault key
    api = makeApi(server);
    token = await api.login(stored.email, account.auth_secret);
    const vault = await api.getVault(token);
    const { items, contacts, lockedRecords } = loadVaultState(account, vault.items);
    session = { account, token, email: stored.email, server, items, contacts, lockedRecords, expiresAt: stored.expiresAt };
    chrome.action.setBadgeText({ text: "✓" });
    chrome.action.setBadgeBackgroundColor({ color: "#5a47e6" });
    return session;
  } catch (error) {
    if (error instanceof VaultIntegrityError) {
      if (token && api) api.logout(token).catch(() => {});
      try { account?.lock(); } catch { /* already locked */ }
      await chrome.storage.session.remove(SESSION_KEY);
    }
    // Rehydration failed (server unreachable, expired data…) — stay locked but
    // keep the stored blob so a later attempt can retry until it actually expires.
    return null;
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) lock();
});

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
  let loaded;
  try {
    loaded = loadVaultState(account, vault.items);
  } catch (error) {
    api.logout(token).catch(() => {});
    account.lock();
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
  const { items, contacts, lockedRecords } = loaded;

  session = { account, token, email, server, items, contacts, lockedRecords };
  await persistSession();
  await touchSession();
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

// Login items whose site matches the given host (incl. equivalent domains),
// newest first.
function suggestionsFor(s, host) {
  return [...s.items.values()]
    .filter((it) => it.type === "login" && (it.username || it.password))
    .filter((it) => matchesSite(it.url || it.title, host))
    .sort(sortItems)
    .map((it) => ({ id: it.id, title: it.title, username: it.username || "" }));
}

// ── credential autofill (injected into the active tab on demand) ──
async function fillActiveTab(item, expectedTabId) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const policyError = autofillPolicyError(item, tab, expectedTabId);
  if (policyError) throw new Error(policyError);
  // Top frame ONLY: filling all frames would write the password into any
  // (possibly malicious, cross-origin) embedded iframe with a password field.
  const results = await chrome.scripting.executeScript({
    target: { tabId: tab.id, frameIds: [0] },
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

  const visible = (el) => {
    if (!el || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 4 || r.height < 4) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== "hidden" && cs.display !== "none" && Number(cs.opacity) > 0.05;
  };

  const pw = Array.from(document.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')).find(visible);
  let user = null;

  if (pw) {
    const scope = pw.form || document;
    const cands = Array.from(scope.querySelectorAll("input")).filter(
      (i) =>
        i !== pw &&
        i.type !== "password" &&
        !i.disabled &&
        !i.readOnly &&
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
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Reject privileged verbs from non-extension senders (content scripts on web
  // pages). A web page can't reach this listener directly (no
  // externally_connectable), but this contains the blast radius if our own
  // content script is ever coerced, and forces content traffic through the
  // host-scoped SUGGEST/CREDS path only.
  const isExtPage = !!sender?.url && sender.url.startsWith(EXT_ORIGIN);
  if (!isExtPage && !CONTENT_ALLOWED.has(msg?.type)) {
    sendResponse({ ok: false, error: "forbidden" });
    return false;
  }
  const senderHost = isExtPage ? null : hostFromSender(sender);

  (async () => {
    try {
      switch (msg?.type) {
        case "STATE": {
          const s = await ensureSession();
          if (s) await touchSession();
          const server = s?.server || (await getServerUrl());
          sendResponse({ ok: true, locked: !s, email: s?.email || null, server, count: s ? s.items.size : 0 });
          break;
        }
        case "UNLOCK":
          await doUnlock(msg.email, msg.password, msg.secretKey);
          sendResponse({ ok: true });
          break;
        case "LOCK":
          await lock();
          sendResponse({ ok: true });
          break;
        case "LIST": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          sendResponse({ ok: true, items: [...s.items.values()].map(toMeta).sort(sortItems) });
          break;
        }
        case "REVEAL": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          sendResponse({ ok: true, value: it[msg.field] || "" });
          break;
        }
        case "SUGGEST": {
          // Inline-autofill suggestions for a page's login fields. Returns only
          // non-secret metadata (id/title/username); never passwords. Host comes
          // from the SENDER frame, not the message. Passive — does NOT extend the
          // keep-unlock window.
          const s = await ensureSession();
          if (!s || !senderHost) return sendResponse({ ok: true, items: [] });
          sendResponse({ ok: true, items: suggestionsFor(s, senderHost) });
          break;
        }
        case "CREDS": {
          // The chosen credential for an inline fill done by the content script.
          // Password leaves WASM only here, for the field the user explicitly
          // picked — and ONLY if the item's site matches the sender frame's host
          // (so a frame can't pull credentials for an unrelated site by id).
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          if (!senderHost || !matchesSite(it.url || it.title, senderHost)) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await touchSession(); // explicit user pick → extend the window
          sendResponse({ ok: true, username: it.username || "", password: it.password || "" });
          break;
        }
        case "STAGE_USER": {
          // Username/email typed (often on a prior step than the password).
          if (!senderHost) return sendResponse({ ok: false, error: "forbidden" });
          await setLastUser(msg.username, senderHost);
          sendResponse({ ok: true });
          break;
        }
        case "STAGE_SAVE": {
          // Form submitted with a password — remember it so we can offer to save
          // once the page settles. Host/URL are taken from the SENDER frame, not
          // the message, so a page can't stage a save for another origin.
          if (msg.password && senderHost) {
            const stagedUser = await takeLastUser(senderHost);
            await setPending({
              host: senderHost,
              url: sender.url,
              username: msg.username || stagedUser,
              password: msg.password,
            });
          }
          sendResponse({ ok: true });
          break;
        }
        case "PENDING_SAVE": {
          // Does a staged credential exist for THIS sender frame? Returns only
          // the non-secret bits; the password stays in the worker. Passive — no
          // keep-unlock extension. Host comes from the sender.
          const p = await getPending();
          if (p && senderHost && matchesSite(p.url || p.host, senderHost)) {
            const s = session;
            const dup =
              s && [...s.items.values()].some((it) => it.type === "login" && it.username === p.username && matchesSite(it.url || it.title, senderHost));
            sendResponse({ ok: true, pending: dup ? null : { username: p.username, host: p.host } });
          } else {
            sendResponse({ ok: true, pending: null });
          }
          break;
        }
        case "SAVE_LOGIN": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          const p = await getPending();
          if (!p) return sendResponse({ ok: false, error: "Nothing to save." });
          // The committing frame MUST be the site the credential was staged for.
          // Otherwise a content script on site Y could commit (and, via the
          // dedupe path, overwrite) a credential staged on site X. Host and
          // title are taken from the staged pending (host-bound at STAGE_SAVE),
          // never from the message.
          if (!senderHost || !matchesSite(p.url || p.host, senderHost)) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await touchSession();
          const username = (msg.username ?? p.username) || "";
          const title = p.host;
          const url = p.url || `https://${p.host}`;

          // Update in place if this site+username already exists; else create.
          let item = [...s.items.values()].find(
            (it) => it.type === "login" && it.username === username && matchesSite(it.url || it.title, p.host)
          );
          if (item) {
            item.password = p.password;
            item.updatedAt = Date.now();
          } else {
            item = { id: crypto.randomUUID(), type: "login", title, username, password: p.password, url, updatedAt: Date.now() };
          }
          const blob = JSON.parse(s.account.encrypt_item(JSON.stringify(item), item.id));
          await makeApi(s.server).putItem(s.token, item.id, blob);
          s.items.set(item.id, item);
          await clearPending();
          sendResponse({ ok: true });
          break;
        }
        case "CLEAR_PENDING":
          await clearPending();
          lastUser = null;
          await chrome.storage.session.remove("lastUser");
          sendResponse({ ok: true });
          break;
        case "ITEM": {
          // Full decrypted item for the detail view. The popup is a trusted
          // extension-page context (same trust boundary that already gets
          // individual secrets via REVEAL); content scripts never see this.
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          sendResponse({ ok: true, item: it });
          break;
        }
        case "FILL": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          const filled = await fillActiveTab(it, msg.tabId);
          sendResponse({ ok: true, filled });
          break;
        }
        // ── Bastion Send (extension-page-only; NOT in CONTENT_ALLOWED) ──
        case "SEND_STATE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          const enabled = !!s.account.has_send_identity;
          let bastionId = s.sendBastionId || null;
          if (enabled && !bastionId) {
            try {
              bastionId = (await makeApi(s.server).whoami(s.token))?.bastion_id || null;
              s.sendBastionId = bastionId;
            } catch {
              bastionId = null;
            }
          }
          sendResponse({ ok: true, enabled, bastionId });
          break;
        }
        case "SEND_ENABLE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const api = makeApi(s.server);
          let who = null;
          try {
            who = await api.whoami(s.token);
          } catch (e) {
            if (!(e instanceof ApiError && e.status === 404)) throw e; // 404 = not published yet
          }
          if (s.account.has_send_identity) {
            // Identity already created locally. Make sure it's published (this
            // self-heals an earlier publish that failed, e.g. a stale server).
            const bastionId =
              who?.bastion_id ||
              (await api.publishIdentity(s.token, JSON.parse(s.account.send_identity_public()))).bastion_id;
            s.sendBastionId = bastionId;
            sendResponse({ ok: true, bastionId });
            break;
          }
          if (who) {
            // Published on another device, but this device holds no identity item.
            sendResponse({
              ok: false,
              error: "Send is already enabled on another device. Unlock that device to use Send here.",
            });
            break;
          }
          // Fresh enable: create identity → persist the reserved vault item → publish.
          const itemBlob = JSON.parse(s.account.create_send_identity());
          await api.putItem(s.token, SEND_IDENTITY_ID, itemBlob);
          const pub = JSON.parse(s.account.send_identity_public());
          const res = await api.publishIdentity(s.token, pub);
          s.sendBastionId = res.bastion_id;
          sendResponse({ ok: true, bastionId: res.bastion_id });
          break;
        }
        case "CONTACTS_LIST": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          sendResponse({ ok: true, contacts: s.contacts || [] });
          break;
        }
        case "SEND_COMPOSE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          if (!s.account.has_send_identity) return sendResponse({ ok: false, error: "Enable Send first." });
          const contact = (s.contacts || []).find((c) => c.bastion_id === msg.recipientId);
          if (!contact) return sendResponse({ ok: false, error: "Unknown recipient." });
          if (!msg.plaintext) return sendResponse({ ok: false, error: "Write a note first." });
          // BR6: for a verified contact, refuse if the published key changed.
          if (contact.verified) {
            try {
              const live = await makeApi(s.server).directory(s.token, contact.bastion_id);
              if ((await sha256hex(canonPublic(live))) !== contact.pinFp) {
                return sendResponse({ ok: false, error: "key-changed", keyChanged: true });
              }
            } catch {
              /* directory unreachable → fall back to the pinned key (offline) */
            }
          }
          let myId;
          try {
            myId = await senderIdForMode({
              signed: !!msg.signed,
              cachedId: s.sendBastionId,
              lookup: async () => {
                const id = (await makeApi(s.server).whoami(s.token))?.bastion_id || null;
                s.sendBastionId = id;
                return id;
              },
            });
          } catch {
            return sendResponse({ ok: false, error: SIGNING_UNAVAILABLE });
          }
          // Seal to the PINNED public (BR6), not a fresh directory fetch.
          const blob = JSON.parse(
            s.account.send_seal(
              msg.plaintext,
              contact.bastion_id,
              JSON.stringify(contact.public),
              msg.passphrase || undefined,
              myId || undefined
            )
          );
          try {
            await makeApi(s.server).sendBlob(s.token, {
              recipient_id: blob.recipient_id,
              message_id: blob.message_id,
              blob,
              expires_at: msg.expiresAt || null,
            });
          } catch (e) {
            const code = e instanceof ApiError ? e.status : 0;
            const map = {
              413: "Message is too large (256 KiB max).",
              409: "This message was already sent.",
              429: "Too many sends, or the recipient's inbox is full. Try again later.",
              404: "Recipient not found — they may have disabled Send.",
              0: "Server unreachable. Nothing was sent.",
            };
            return sendResponse({ ok: false, error: map[code] || e?.message || "Send failed." });
          }
          sendResponse({ ok: true });
          break;
        }
        case "SEND_INBOX": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          let list;
          try {
            list = await makeApi(s.server).inbox(s.token);
          } catch (e) {
            return sendResponse({ ok: false, error: e?.message || "Could not load inbox." });
          }
          s.inboxCache = new Map();
          const messages = [];
          for (const m of list || []) {
            s.inboxCache.set(m.message_id, { blob: m.blob, created_at: m.created_at });
            const opened = openMessage(s, m.blob, undefined);
            // NO-PERSIST enforcement: if the sender is a lock-enabled contact,
            // never return the identity-decrypted plaintext — surface a locked
            // placeholder; the plaintext is discarded (sealed-sender means we had
            // to decrypt in RAM just to learn the sender).
            const lc = opened.sender?.id ? lockContactFor(s, opened.sender.id) : null;
            if (lc) {
              // Idempotency: if this message was already locked (a prior finalize
              // whose inbox-delete failed), don't show a duplicate pending row —
              // the locked record is listed below; just clear the server copy.
              if ((s.lockedRecords || []).some((r) => r.message_id === m.message_id)) {
                try { await makeApi(s.server).inboxDelete(s.token, m.message_id); } catch { /* retry next load */ }
                continue;
              }
              messages.push({ message_id: m.message_id, created_at: m.created_at, locked: true, pending: true, contactId: lc.bastion_id, display: lc.display });
            } else {
              messages.push({ message_id: m.message_id, created_at: m.created_at, expires_at: m.expires_at, ...opened });
            }
          }
          // Already-locked records (vault items) shown as locked rows, deduped
          // by message_id (concurrent dual-device finalizes mint distinct items).
          const seenLocked = new Set();
          for (const r of s.lockedRecords || []) {
            if (seenLocked.has(r.message_id)) continue;
            seenLocked.add(r.message_id);
            const c = (s.contacts || []).find((x) => x.bastion_id === r.contact_id);
            messages.push({ local_id: r.local_id, created_at: r.created_at, locked: true, pending: false, contactId: r.contact_id, display: c?.display || r.contact_id });
          }
          messages.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
          sendResponse({ ok: true, messages });
          break;
        }
        case "SEND_OPEN": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const cached = s.inboxCache?.get(msg.messageId);
          if (!cached) return sendResponse({ ok: false, error: "Message is no longer available." });
          const opened = openMessage(s, cached.blob, msg.passphrase);
          if (opened.error) return sendResponse({ ok: false, error: opened.error, needsPass: opened.needsPass });
          // NO-PERSIST guard at the trust boundary: if opening revealed a
          // lock-enabled contact (e.g. a sender-passphrase'd message whose sender
          // we couldn't see at list time), NEVER return the plaintext — route to
          // the lock-phrase secure flow instead.
          const lc = opened.sender?.id ? lockContactFor(s, opened.sender.id) : null;
          if (lc) {
            return sendResponse({ ok: true, locked: true, pending: true, message_id: msg.messageId, contactId: lc.bastion_id, display: lc.display });
          }
          sendResponse({ ok: true, message_id: msg.messageId, ...opened });
          break;
        }
        case "CONTACTS_SET_LOCK": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const contact = (s.contacts || []).find((c) => c.bastion_id === msg.bastionId);
          if (!contact) return sendResponse({ ok: false, error: "Unknown contact." });
          if (contact.lock_enabled) return sendResponse({ ok: true }); // already on
          const params = JSON.parse(send_lock_new_params());
          contact.lock_enabled = true;
          contact.lock_salt = params.salt;
          contact.lock_kdf = params.kdf;
          await saveContacts(s);
          sendResponse({ ok: true });
          break;
        }
        case "SEND_LOCK_FINALIZE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          if (!msg.phrase || msg.phrase.length < 8) {
            return sendResponse({ ok: false, error: "Lock phrase must be at least 8 characters." });
          }
          const cached = s.inboxCache?.get(msg.messageId);
          if (!cached) return sendResponse({ ok: false, error: "Message is no longer available." });
          const contact = lockContactFor(s, msg.contactId);
          if (!contact) return sendResponse({ ok: false, error: "This contact has no lock phrase." });
          let recordJson;
          try {
            recordJson = s.account.send_lock_finalize(
              JSON.stringify(cached.blob),
              contact.bastion_id,
              cached.created_at || 0,
              msg.passphrase || undefined, // sender passphrase, if the message had one
              contact.verified ? JSON.stringify(contact.public) : undefined,
              msg.phrase,
              contact.lock_salt,
              JSON.stringify(contact.lock_kdf)
            );
          } catch {
            return sendResponse({ ok: false, error: "Could not lock this message." });
          }
          const record = JSON.parse(recordJson);
          const itemId = SEND_LOCKED_PREFIX + record.local_id;
          const itemBlob = JSON.parse(s.account.encrypt_item(recordJson, itemId));
          await makeApi(s.server).putItem(s.token, itemId, itemBlob); // persist BEFORE delete
          s.lockedRecords.push(record);
          try { await makeApi(s.server).inboxDelete(s.token, msg.messageId); } catch { /* retry later */ }
          s.inboxCache.delete(msg.messageId);
          const opened = JSON.parse(send_lock_open(recordJson, msg.phrase, contact.lock_salt, JSON.stringify(contact.lock_kdf)));
          sendResponse({ ok: true, local_id: record.local_id, display: contact.display, ...opened });
          break;
        }
        case "SEND_LOCK_OPEN": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const record = (s.lockedRecords || []).find((r) => r.local_id === msg.localId);
          if (!record) return sendResponse({ ok: false, error: "Message is no longer available." });
          const contact = (s.contacts || []).find((c) => c.bastion_id === record.contact_id && c.lock_enabled);
          if (!contact) return sendResponse({ ok: false, error: "Contact lock data missing." });
          let opened;
          try {
            opened = JSON.parse(send_lock_open(JSON.stringify(record), msg.phrase, contact.lock_salt, JSON.stringify(contact.lock_kdf)));
          } catch {
            return sendResponse({ ok: false, error: "Wrong lock phrase." });
          }
          sendResponse({ ok: true, local_id: record.local_id, display: contact.display, ...opened });
          break;
        }
        case "SEND_LOCK_DELETE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          try { await makeApi(s.server).deleteItem(s.token, SEND_LOCKED_PREFIX + msg.localId); } catch { /* already gone */ }
          s.lockedRecords = (s.lockedRecords || []).filter((r) => r.local_id !== msg.localId);
          sendResponse({ ok: true });
          break;
        }
        case "SEND_INBOX_DELETE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          try {
            await makeApi(s.server).inboxDelete(s.token, msg.messageId);
          } catch {
            /* already gone; treat as deleted */
          }
          s.inboxCache?.delete(msg.messageId);
          sendResponse({ ok: true });
          break;
        }
        case "CONTACTS_RESOLVE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          if (!s.account.has_send_identity) return sendResponse({ ok: false, error: "Enable Send first." });
          const id = (msg.bastionId || "").trim().toUpperCase();
          if (!id) return sendResponse({ ok: false, error: "Enter a Bastion address." });
          let myId = s.sendBastionId;
          if (!myId) {
            try { myId = (await makeApi(s.server).whoami(s.token))?.bastion_id || null; s.sendBastionId = myId; } catch { /* unpublished */ }
          }
          if (!myId) return sendResponse({ ok: false, error: "Publish your own address first." });
          if (id === myId) return sendResponse({ ok: false, error: "That's your own address." });
          let theirPub;
          try {
            theirPub = await makeApi(s.server).directory(s.token, id);
          } catch (e) {
            return sendResponse({
              ok: false,
              error: e instanceof ApiError && e.status === 404 ? "No Bastion user has that address." : e?.message || "Lookup failed.",
            });
          }
          const myPub = JSON.parse(s.account.send_identity_public());
          const safety = send_safety_number(myId, JSON.stringify(myPub), id, JSON.stringify(theirPub));
          const pinFp = await sha256hex(canonPublic(theirPub));
          sendResponse({ ok: true, bastionId: id, public: theirPub, pinFp, safety_number: safety });
          break;
        }
        case "CONTACTS_SAVE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const c = {
            bastion_id: msg.bastionId,
            public: msg.public,
            pinFp: msg.pinFp,
            display: (msg.display || "").trim() || msg.bastionId,
            verified: !!msg.verified,
            verified_at: msg.verified ? Date.now() : null,
            safety_number: msg.safety_number || null,
          };
          s.contacts = (s.contacts || []).filter((x) => x.bastion_id !== c.bastion_id);
          s.contacts.push(c);
          await saveContacts(s);
          sendResponse({ ok: true });
          break;
        }
        case "CONTACTS_DELETE": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await touchSession();
          const gone = (s.contacts || []).find((c) => c.bastion_id === msg.bastionId);
          // Hard-delete the contact's locked messages (design §7): they become
          // permanently unreadable, honoring the lock-phrase warning.
          const orphaned = (s.lockedRecords || []).filter((r) => r.contact_id === msg.bastionId);
          for (const r of orphaned) {
            try { await makeApi(s.server).deleteItem(s.token, SEND_LOCKED_PREFIX + r.local_id); } catch { /* already gone */ }
          }
          // For a lock contact, also purge any STILL-PENDING (un-secured) inbox
          // messages from them — otherwise they'd revert to readable once the
          // contact (and its lock flag) is gone, contradicting the warning.
          if (gone?.lock_enabled) {
            try {
              const list = await makeApi(s.server).inbox(s.token);
              for (const m of list || []) {
                const opened = openMessage(s, m.blob, undefined);
                if (opened.sender?.id === msg.bastionId) {
                  try { await makeApi(s.server).inboxDelete(s.token, m.message_id); } catch { /* best effort */ }
                }
              }
            } catch { /* inbox unreachable; best effort */ }
          }
          s.lockedRecords = (s.lockedRecords || []).filter((r) => r.contact_id !== msg.bastionId);
          s.contacts = (s.contacts || []).filter((x) => x.bastion_id !== msg.bastionId);
          await saveContacts(s);
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: "Unknown message." });
      }
    } catch (e) {
      sendResponse({ ok: false, error: e?.message || String(e) });
    }
  })();
  return true; // keep the channel open for the async response
});
