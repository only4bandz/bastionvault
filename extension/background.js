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
// Only a non-secret rollback checkpoint is persisted separately so manifest
// rollback remains detectable across a complete browser restart.

import init, { unlock, rehydrate, send_safety_number, send_lock_open, send_lock_new_params } from "./pkg/crypto_wasm.js";
import {
  autofillPolicyError,
  credentialPageError,
  validatedAutofillTarget,
  frameAutofillError,
} from "./lib/autofill-policy.js";
import { makeApi, ApiError } from "./lib/api.js";
import { IDLE_DETECTION_SECONDS, shouldLockOnIdleState } from "./lib/idle-lock.js";
import { assertUnlockKdfPolicy } from "./lib/kdf-policy.js";
import { revealFieldValue } from "./lib/reveal-policy.js";
import { CLIPBOARD_CLEAR_MS } from "./lib/clipboard-clear.js";
import { validContentMessage } from "./lib/content-message-policy.js";
import { matchesSite } from "./lib/match.js";
import { makeStagedUsername, stagedUsernameFor } from "./lib/staged-username.js";
import {
  makePendingSave,
  pendingSaveExpiresAt,
  pendingSaveIsExpired,
} from "./lib/pending-save.js";
import {
  completeBootstrap,
  completeVaultMutation,
  decryptVerifiedVaultState,
  loadLegacyVaultState,
  prepareBootstrapManifest,
  prepareVaultMutation,
  reconcileVaultMutation,
  verifyVaultSnapshot,
  vaultRefreshRequired,
  VaultIntegrityError,
} from "./lib/vault-load.js";
import {
  VaultRollbackError,
  assertVaultRollbackProgress,
  createVaultRollbackAnchor,
  readVaultRollbackAnchor,
  vaultRollbackAnchorKey,
  withVaultRollbackLock,
  writeVaultRollbackAnchor,
} from "./lib/vault-anchor.js";
import { DEFAULT_SERVER, normalizeServerUrl } from "./lib/server-url.js";
import { SIGNING_UNAVAILABLE, senderIdForMode } from "./lib/send-policy.js";
import { openMessage as openSendMessage } from "./lib/send-open.js";
import { requireTrustedStorageArea } from "./lib/trusted-storage.js";
import {
  CONTENT_SENDER,
  POPUP_SENDER,
  classifyMessageSender,
} from "./lib/message-sender-policy.js";

const DEFAULT_KEEP_MINUTES = 60;
const AUTOLOCK_ALARM = "bastion-autolock";
const PENDING_SAVE_ALARM = "bastion-pending-save-expiry";
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
async function saveContacts(s, contacts = s.contacts || []) {
  const blob = JSON.parse(s.account.encrypt_item(JSON.stringify(contacts), SEND_CONTACTS_ID));
  await commitVaultOperations(s, [{ op: "put", id: SEND_CONTACTS_ID, blob }]);
  s.contacts = contacts;
}

function openMessage(s, blob, passphrase) {
  return openSendMessage(s.account, s.contacts || [], blob, passphrase);
}
// Every session-storage operation awaits this guard. The session area carries
// the exported vault key and staged passwords, so an absent or rejected access
// control API must stop the operation instead of silently widening exposure.
let trustedSessionAreaPromise;
function trustedSessionArea() {
  if (!trustedSessionAreaPromise) {
    trustedSessionAreaPromise = requireTrustedStorageArea(chrome.storage.session).catch((error) => {
      trustedSessionAreaPromise = null;
      throw error;
    });
  }
  return trustedSessionAreaPromise;
}
chrome.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});

// Messages a content script (running on arbitrary web pages) is allowed to send.
// Everything else (LIST/ITEM/REVEAL/FILL/UNLOCK/LOCK/STATE) is for extension
// pages only — see the sender check in the message router.
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
// { account, token, email, server, items: Map<id, item>, integrity, mutationTail }
let session = null;

function legacyCheckpointFromStored(stored) {
  if (stored.revision === undefined && stored.manifestSeq === undefined) return null;
  if (
    !Number.isSafeInteger(stored.revision) ||
    stored.revision < 0 ||
    typeof stored.manifestSeq !== "string" ||
    !/^(0|[1-9][0-9]{0,19})$/.test(stored.manifestSeq)
  ) {
    throw new VaultIntegrityError();
  }
  const manifestSeq = BigInt(stored.manifestSeq);
  if (manifestSeq > (1n << 64n) - 1n) throw new VaultIntegrityError();
  return { revision: stored.revision, manifestSeq };
}

async function trustedAnchorArea() {
  if (typeof chrome.storage.local.setAccessLevel !== "function") {
    throw new VaultRollbackError("Trusted extension storage isolation is unavailable.");
  }
  try {
    await chrome.storage.local.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
  } catch {
    throw new VaultRollbackError("Trusted extension storage isolation could not be enforced.");
  }
  return chrome.storage.local; // storage-guard:allow -- non-secret rollback metadata only
}

async function loadSessionVault(account, api, token, vault, checkpoint = null, trusted = null) {
  if (vault?.manifest) {
    const integrity = verifyVaultSnapshot(account, vault, {
      lastSeenSeq: checkpoint?.manifestSeq,
      minimumRevision: checkpoint?.revision,
    });
    const rollbackAnchor = await createVaultRollbackAnchor(integrity);
    assertVaultRollbackProgress(rollbackAnchor, trusted);
    return {
      ...decryptVerifiedVaultState(account, vault, integrity),
      integrity,
      rollbackAnchor,
    };
  }
  // A manifest disappearing while any trusted checkpoint exists is a
  // rollback, never a legacy bootstrap.
  if (checkpoint) throw new VaultIntegrityError();
  const decrypted = loadLegacyVaultState(account, vault);
  const bootstrap = prepareBootstrapManifest(account, vault);
  const result = await api.mutateVault(token, vault.revision, [], bootstrap.manifest);
  const integrity = completeBootstrap(account, vault, bootstrap, result.revision);
  return {
    ...decrypted,
    integrity,
    rollbackAnchor: await createVaultRollbackAnchor(integrity),
    bootstrapped: true,
  };
}

function combineCheckpointFloors(persisted, legacy) {
  if (!persisted) return legacy;
  if (!legacy) return persisted;
  return {
    revision: Math.max(persisted.revision, legacy.revision),
    manifestSeq:
      persisted.manifestSeq > legacy.manifestSeq
        ? persisted.manifestSeq
        : legacy.manifestSeq,
  };
}

async function loadSessionVaultAnchored(
  account,
  api,
  token,
  vault,
  email,
  server,
  legacyCheckpoint = null
) {
  const key = vaultRollbackAnchorKey(server, email);
  return withVaultRollbackLock(key, async () => {
    const area = await trustedAnchorArea();
    const trusted = await readVaultRollbackAnchor(area, key);
    const checkpoint = combineCheckpointFloors(trusted, legacyCheckpoint);
    const loaded = await loadSessionVault(account, api, token, vault, checkpoint, trusted);
    await writeVaultRollbackAnchor(area, key, loaded.rollbackAnchor);
    return loaded;
  });
}

async function persistVaultIntegrityAnchor(currentSession) {
  const key = vaultRollbackAnchorKey(currentSession.server, currentSession.email);
  await withVaultRollbackLock(key, async () => {
    const area = await trustedAnchorArea();
    const candidate = await createVaultRollbackAnchor(currentSession.integrity);
    await writeVaultRollbackAnchor(area, key, candidate);
  });
}

async function commitVaultOperations(s, operations) {
  const execute = async () => {
    try {
      if (session !== s) throw new VaultIntegrityError();
      const current = s.integrity;
      if (!current) throw new VaultIntegrityError();
      const prepared = prepareVaultMutation(s.account, current, operations);
      const api = makeApi(s.server);
      let result;
      try {
        result = await api.mutateVault(
          s.token,
          current.revision,
          prepared.operations,
          prepared.manifest
        );
      } catch (error) {
        const ambiguous =
          error instanceof ApiError && (error.status === 0 || error.status >= 500);
        if (ambiguous && session === s) {
          try {
            const remote = await api.getVault(s.token);
            const reconciled = reconcileVaultMutation(s.account, current, prepared, remote);
            if (reconciled && session === s) {
              s.integrity = reconciled;
              await persistSession();
              return;
            }
          } catch {
            // The original mutation remains ambiguous. The outer handler locks
            // before any caller can publish speculative local state.
          }
        }
        throw error;
      }
      if (session !== s) return;
      s.integrity = completeVaultMutation(s.account, current, prepared, result.revision);
      await persistSession();
    } catch (error) {
      const mustLock =
        error instanceof VaultIntegrityError ||
        !(error instanceof ApiError) ||
        [0, 401, 409].includes(error.status) ||
        error.status >= 500;
      if (mustLock && session === s) await lock();
      throw error;
    }
  };
  const scheduled = (s.mutationTail || Promise.resolve()).then(execute, execute);
  s.mutationTail = scheduled.then(
    () => undefined,
    () => undefined
  );
  return scheduled;
}

// Re-read and verify the remote vault before returning decrypted item data.
// The web app can soft-delete an item while this worker remains unlocked; a
// cached item must not keep releasing secrets after that deletion. Refreshes
// share the mutation queue so they cannot race a local extension write.
async function refreshSessionVault(s) {
  const execute = async () => {
    try {
      if (session !== s || !s.integrity) throw new VaultIntegrityError();
      const api = makeApi(s.server);
      const head = await api.getVaultRevision(s.token);
      if (!vaultRefreshRequired(s.integrity.revision, head?.revision)) return;
      const vault = await api.getVault(s.token);
      const checkpoint = {
        revision: s.integrity.revision,
        manifestSeq: s.integrity.manifestSeq,
      };
      const loaded = await loadSessionVaultAnchored(
        s.account,
        api,
        s.token,
        vault,
        s.email,
        s.server,
        checkpoint
      );
      if (loaded.integrity.revision < head.revision) throw new VaultIntegrityError();
      if (session !== s) throw new VaultIntegrityError();
      s.items = loaded.items;
      s.contacts = loaded.contacts;
      s.lockedRecords = loaded.lockedRecords;
      s.integrity = loaded.integrity;
      await persistSession();
    } catch (error) {
      const mustLock =
        error instanceof VaultIntegrityError ||
        error instanceof VaultRollbackError ||
        (error instanceof ApiError && error.status === 401);
      if (mustLock && session === s) await lock();
      throw error;
    }
  };
  const scheduled = (s.mutationTail || Promise.resolve()).then(execute, execute);
  s.mutationTail = scheduled.then(
    () => undefined,
    () => undefined
  );
  return scheduled;
}

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
  const area = await trustedSessionArea();
  const stored = await area.get(SESSION_KEY);
  if (stored[SESSION_KEY]) {
    stored[SESSION_KEY].expiresAt = expiresAt;
    await area.set({ [SESSION_KEY]: stored[SESSION_KEY] });
  }
  return expiresAt;
}

async function persistSession() {
  if (!session) return;
  if (!session.integrity) throw new VaultIntegrityError();
  await persistVaultIntegrityAnchor(session);
  const minutes = await getKeepMinutes();
  if (!session.expiresAt) session.expiresAt = Date.now() + minutes * 60_000;
  const area = await trustedSessionArea();
  await area.set({
    [SESSION_KEY]: {
      crypto: session.account.export_session(), // contains the vault key (RAM only)
      email: session.email,
      server: session.server,
      expiresAt: session.expiresAt,
    },
  });
}

// ── pending "save this login?" (staged at form submit, survives the navigation
// that follows via storage.session; plaintext lives in RAM only until the user
// saves or dismisses) ──
let pendingSave = null;
let lastUser = null; // origin-bound username for multi-step sign-ups
async function setPending(p) {
  pendingSave = makePendingSave(p);
  const area = await trustedSessionArea();
  await area.set({ pendingSave });
  chrome.alarms.create(PENDING_SAVE_ALARM, { when: pendingSaveExpiresAt(pendingSave) });
}
async function getPending() {
  const area = await trustedSessionArea();
  if (!pendingSave) pendingSave = (await area.get("pendingSave")).pendingSave || null;
  // Expire a staged credential so a plaintext password never lingers.
  if (pendingSaveIsExpired(pendingSave)) {
    await clearPending();
    return null;
  }
  return pendingSave;
}
async function clearPending() {
  pendingSave = null;
  const area = await trustedSessionArea();
  await area.remove("pendingSave");
  await chrome.alarms.clear(PENDING_SAVE_ALARM);
}

async function setLastUser(username, host) {
  lastUser = makeStagedUsername(username, host);
  const area = await trustedSessionArea();
  if (lastUser) await area.set({ lastUser });
  else await area.remove("lastUser");
}

async function takeLastUser(host) {
  const area = await trustedSessionArea();
  if (!lastUser) lastUser = (await area.get("lastUser")).lastUser || null;
  const username = stagedUsernameFor(lastUser, host);
  lastUser = null;
  await area.remove("lastUser");
  return username;
}

// ── Offscreen document: owns the clipboard-clear timer (see offscreen.js) ──
let offscreenReady;
async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  if (!offscreenReady) {
    offscreenReady = chrome.offscreen
      .createDocument({
        url: "offscreen.html",
        reasons: ["CLIPBOARD"],
        justification: "Clear copied secrets from the clipboard after a delay.",
      })
      .catch(() => {})
      .finally(() => {
        offscreenReady = null;
      });
  }
  await offscreenReady;
}

async function scheduleClipboardClear(delayMs) {
  await ensureOffscreen();
  chrome.runtime
    .sendMessage({ target: "offscreen-clipboard", type: "CLIP_SCHEDULE_CLEAR", delayMs })
    .catch(() => {});
}

async function clearClipboardNow() {
  await ensureOffscreen();
  chrome.runtime
    .sendMessage({ target: "offscreen-clipboard", type: "CLIP_CLEAR_NOW" })
    .catch(() => {});
}

async function lock() {
  await clearClipboardNow(); // copied secrets must not outlive the session
  await clearPending(); // don't leave a staged plaintext password around
  lastUser = null;
  const area = await trustedSessionArea();
  await area.remove("lastUser");
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
  await area.remove(SESSION_KEY);
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

  const area = await trustedSessionArea();
  const stored = (await area.get(SESSION_KEY))[SESSION_KEY];
  if (!stored) return null;
  if (Date.now() > stored.expiresAt) {
    await area.remove(SESSION_KEY);
    return null;
  }

  let server;
  try {
    server = normalizeServerUrl(stored.server).url;
  } catch {
    await area.remove(SESSION_KEY);
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
    const checkpoint = legacyCheckpointFromStored(stored);
    const { items, contacts, lockedRecords, integrity } = await loadSessionVaultAnchored(
      account,
      api,
      token,
      vault,
      stored.email,
      server,
      checkpoint
    );
    session = {
      account,
      token,
      email: stored.email,
      server,
      items,
      contacts,
      lockedRecords,
      integrity,
      mutationTail: Promise.resolve(),
      expiresAt: stored.expiresAt,
    };
    await persistSession();
    chrome.action.setBadgeText({ text: "✓" });
    chrome.action.setBadgeBackgroundColor({ color: "#5a47e6" });
    return session;
  } catch (error) {
    if (token && api) api.logout(token).catch(() => {});
    try { account?.lock(); } catch { /* already locked */ }
    if (error instanceof VaultIntegrityError || error instanceof VaultRollbackError) {
      await area.remove(SESSION_KEY);
    }
    // Integrity failures discard the rehydration blob. Transient failures keep
    // it so a later attempt can retry until the bounded session expires.
    return null;
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTOLOCK_ALARM) lock();
  if (alarm.name === PENDING_SAVE_ALARM) clearPending();
});

// The keep-unlocked window must not outlive the user's presence: when the OS
// session locks (screen lock, fast user switching, suspend), lock the vault
// immediately. See lib/idle-lock.js for why "idle" alone does not lock.
chrome.idle.setDetectionInterval(IDLE_DETECTION_SECONDS);
chrome.idle.onStateChanged.addListener((state) => {
  if (shouldLockOnIdleState(state)) lock();
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

  assertUnlockKdfPolicy(pre.kdf);

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

  let token;
  let loaded;
  try {
    token = await api.login(email, account.auth_secret);
    const vault = await api.getVault(token);
    loaded = await loadSessionVaultAnchored(account, api, token, vault, email, server);
  } catch (error) {
    if (token) api.logout(token).catch(() => {});
    account.lock();
    throw error;
  }
  const { items, contacts, lockedRecords, integrity } = loaded;

  session = {
    account,
    token,
    email,
    server,
    items,
    contacts,
    lockedRecords,
    integrity,
    mutationTail: Promise.resolve(),
  };
  try {
    await persistSession();
    await touchSession();
  } catch (error) {
    await lock();
    throw error;
  }
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

  // Probe the top frame without secrets. The returned documentId is a stable
  // identity for this exact document, unlike tabId/frameId which survive a
  // navigation and could otherwise retarget the credential injection.
  const probe = await chrome.scripting.executeScript({
    target: { tabId: tab.id, frameIds: [0] },
    func: currentDocumentUrl,
  });
  const target = validatedAutofillTarget(item, tab, expectedTabId, probe);

  // documentIds and frameIds are intentionally not combined. If navigation
  // replaced the validated document, Chrome rejects the stale documentId and
  // the credentials are never delivered to the replacement page.
  try {
    const results = await chrome.scripting.executeScript({
      target,
      args: [{ username: item.username || "", password: item.password || "" }],
      func: injectedFill,
    });
    return results.some(
      (result) =>
        result.documentId === target.documentIds[0] && result.frameId === 0 && result.result === true
    );
  } catch {
    throw new Error("The active page changed. Reopen Bastion before filling.");
  }
}

// Runs without arguments and returns no page content beyond the current URL.
// It is serialized by chrome.scripting, so it must remain self-contained.
function currentDocumentUrl() {
  return globalThis.location.href;
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
  const senderKind = classifyMessageSender(
    sender,
    chrome.runtime.id,
    chrome.runtime.getURL("popup.html")
  );
  const isExtPage = senderKind === POPUP_SENDER;
  if (
    (!isExtPage && senderKind !== CONTENT_SENDER) ||
    (senderKind === CONTENT_SENDER && !validContentMessage(msg))
  ) {
    sendResponse({ ok: false, error: "forbidden" });
    return false;
  }
  const senderHost = isExtPage ? null : hostFromSender(sender);
  const senderCredentialError = isExtPage ? "forbidden" : credentialPageError(sender?.url);
  // Third-party-iframe guard: the sender frame only gets autofill traffic when
  // its registrable site matches the TOP page the user actually sees.
  const senderFrameError = isExtPage
    ? "forbidden"
    : frameAutofillError(sender?.url, sender?.tab?.url);

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
          await refreshSessionVault(s);
          await touchSession();
          sendResponse({ ok: true, items: [...s.items.values()].map(toMeta).sort(sortItems) });
          break;
        }
        case "REVEAL": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await refreshSessionVault(s);
          await touchSession();
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          sendResponse({ ok: true, value: revealFieldValue(it, msg.field) });
          break;
        }
        case "SUGGEST": {
          // Inline-autofill suggestions for a page's login fields. Returns only
          // non-secret metadata (id/title/username); never passwords. Host comes
          // from the SENDER frame, not the message. Passive — does NOT extend the
          // keep-unlock window.
          const s = await ensureSession();
          if (!s || !senderHost || senderCredentialError || senderFrameError) {
            return sendResponse({ ok: true, items: [] });
          }
          sendResponse({ ok: true, items: suggestionsFor(s, senderHost) });
          break;
        }
        case "CREDS": {
          // The chosen credential for an inline fill done by the content script.
          // Password leaves WASM only here, for the field the user explicitly
          // picked — and ONLY if the item's site matches the sender frame's host
          // (so a frame can't pull credentials for an unrelated site by id).
          if (senderCredentialError || senderFrameError) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await refreshSessionVault(s);
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
          // Insecure-HTTP pages can be attacker-authored (network MITM): they
          // must not feed the save pipeline either — same rule as fills.
          if (!senderHost || senderCredentialError) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await setLastUser(msg.username, senderHost);
          sendResponse({ ok: true });
          break;
        }
        case "STAGE_SAVE": {
          // Form submitted with a password — remember it so we can offer to save
          // once the page settles. Host/URL are taken from the SENDER frame, not
          // the message, so a page can't stage a save for another origin.
          if (msg.password && senderHost && !senderCredentialError) {
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
          if (p && senderHost && !senderCredentialError && matchesSite(p.url || p.host, senderHost)) {
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
          if (!senderHost || senderCredentialError || !matchesSite(p.url || p.host, senderHost)) {
            return sendResponse({ ok: false, error: "forbidden" });
          }
          await touchSession();
          const username = (msg.username ?? p.username) || "";
          const title = p.host;
          const url = p.url || `https://${p.host}`;

          // Update in place if this site+username already exists; else create.
          const existing = [...s.items.values()].find(
            (it) => it.type === "login" && it.username === username && matchesSite(it.url || it.title, p.host)
          );
          const item = existing
            ? { ...existing, password: p.password, updatedAt: Date.now() }
            : { id: crypto.randomUUID(), type: "login", title, username, password: p.password, url, updatedAt: Date.now() };
          const blob = JSON.parse(s.account.encrypt_item(JSON.stringify(item), item.id));
          await commitVaultOperations(s, [{ op: "put", id: item.id, blob }]);
          s.items.set(item.id, item);
          await clearPending();
          sendResponse({ ok: true });
          break;
        }
        case "CLEAR_PENDING":
          await clearPending();
          lastUser = null;
          await (await trustedSessionArea()).remove("lastUser");
          sendResponse({ ok: true });
          break;
        case "CLIP_CLEAR": {
          // The popup copied a secret and wants it wiped after the delay. The
          // popup's own timer dies when it closes, so the offscreen document
          // owns it. No plaintext crosses here — just the schedule signal.
          await scheduleClipboardClear(CLIPBOARD_CLEAR_MS);
          sendResponse({ ok: true });
          break;
        }
        case "ITEM": {
          // Full decrypted item for the detail view. The popup is a trusted
          // extension-page context (same trust boundary that already gets
          // individual secrets via REVEAL); content scripts never see this.
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await refreshSessionVault(s);
          await touchSession();
          const it = s.items.get(msg.id);
          if (!it) throw new Error("Item not found.");
          sendResponse({ ok: true, item: it });
          break;
        }
        case "FILL": {
          const s = await ensureSession();
          if (!s) return sendResponse({ ok: false, error: "locked", locked: true });
          await refreshSessionVault(s);
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
          try {
            await commitVaultOperations(s, [{ op: "put", id: SEND_IDENTITY_ID, blob: itemBlob }]);
          } catch (error) {
            // Discard create_send_identity's staged private identity even when
            // persistence failed definitively rather than ambiguously.
            if (session === s) await lock();
            throw error;
          }
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
          const contacts = (s.contacts || []).map((candidate) =>
            candidate.bastion_id === msg.bastionId
              ? { ...candidate, lock_enabled: true, lock_salt: params.salt, lock_kdf: params.kdf }
              : candidate
          );
          await saveContacts(s, contacts);
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
          await commitVaultOperations(s, [{ op: "put", id: itemId, blob: itemBlob }]); // persist BEFORE delete
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
          await commitVaultOperations(s, [{ op: "delete", id: SEND_LOCKED_PREFIX + msg.localId }]);
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
          const contacts = (s.contacts || []).filter((x) => x.bastion_id !== c.bastion_id);
          contacts.push(c);
          await saveContacts(s, contacts);
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
          const lockedRecords = (s.lockedRecords || []).filter((r) => r.contact_id !== msg.bastionId);
          const contacts = (s.contacts || []).filter((x) => x.bastion_id !== msg.bastionId);
          const contactsBlob = JSON.parse(
            s.account.encrypt_item(JSON.stringify(contacts), SEND_CONTACTS_ID)
          );
          await commitVaultOperations(s, [
            ...orphaned.map((record) => ({
              op: "delete",
              id: SEND_LOCKED_PREFIX + record.local_id,
            })),
            { op: "put", id: SEND_CONTACTS_ID, blob: contactsBlob },
          ]);
          s.lockedRecords = lockedRecords;
          s.contacts = contacts;
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
