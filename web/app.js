import init, { register, unlock } from "./pkg/crypto_wasm.js";

const $ = (id) => document.getElementById(id);

function log(message, level = "") {
  const line = document.createElement("span");
  line.textContent = String(message);
  if (["ok", "err", "warn"].includes(level)) line.classList.add(level);
  $("log").replaceChildren(line);
}

function renderSecret(reveal) {
  const label = document.createElement("label");
  label.textContent = "Secret Key (keep it safe — shown only once)";

  const secret = document.createElement("pre");
  secret.className = "warn";
  secret.textContent = reveal.secret_key;

  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.className = "hint";
  summary.textContent = "View the Emergency Kit";
  const kit = document.createElement("pre");
  kit.textContent = reveal.emergency_kit;
  details.append(summary, kit);

  $("secret-out").replaceChildren(label, secret, details);
}

// The demo "server" is an in-memory object containing opaque data only.
const server = { registration: null, items: {} };

function renderServer() {
  $("server-view").textContent = JSON.stringify(
    {
      registration: server.registration ? JSON.parse(server.registration) : null,
      items: server.items,
    },
    null,
    2
  );
}

let account = null;

function renderPlain() {
  if (!account || account.is_locked) {
    $("plain-list").textContent = "— (locked)";
    return;
  }
  const lines = Object.keys(server.items).map((id) => {
    try {
      return `${id} = ${account.decrypt_item(server.items[id], id)}`;
    } catch {
      return `${id} = <unreadable>`;
    }
  });
  $("plain-list").textContent = lines.length ? lines.join("\n") : "—";
}

const INACTIVITY_MS = 2 * 60 * 1000;
let idleTimer = null;

function doLock(reason) {
  if (!account || account.is_locked) return;
  account.lock();
  $("btn-add").disabled = true;
  renderPlain();
  log(`Locked (${reason}). Unlock again to read items.`, "warn");
}

function armIdle() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => doLock("inactivity"), INACTIVITY_MS);
}

["mousemove", "keydown", "click"].forEach((event) =>
  window.addEventListener(event, armIdle, { passive: true })
);
window.addEventListener("blur", () => doLock("focus lost"));
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") doLock("tab hidden");
});

await init();
log("WASM module ready. Create a vault to get started.", "ok");

$("btn-register").addEventListener("click", () => {
  try {
    log("Deriving Argon2id…");
    account = register($("reg-pw").value);
    server.registration = account.registration_json;
    server.items = {};
    const reveal = JSON.parse(account.reveal_secret("alice@example.com"));
    renderSecret(reveal);
    $("unlock-sk").value = reveal.secret_key;
    $("unlock-pw").value = $("reg-pw").value;
    $("btn-add").disabled = false;
    $("btn-unlock").disabled = false;
    armIdle();
    renderServer();
    renderPlain();
    log("Vault created. The server only receives opaque data.", "ok");
  } catch (error) {
    log(`Error: ${String(error)}`, "err");
  }
});

$("btn-add").addEventListener("click", () => {
  try {
    const id = $("item-id").value;
    const value = $("item-val").value;
    server.items[id] = account.encrypt_item(value, id);
    armIdle();
    renderServer();
    renderPlain();
    log(`Item "${id}" encrypted client-side then sent to the server.`, "ok");
  } catch (error) {
    log(`Error: ${String(error)}`, "err");
  }
});

$("btn-unlock").addEventListener("click", () => {
  try {
    if (!server.registration) {
      log("Create a vault first.", "warn");
      return;
    }
    log("Unlocking…");
    account = unlock($("unlock-pw").value, $("unlock-sk").value, server.registration);
    $("btn-add").disabled = false;
    armIdle();
    renderPlain();
    log("Unlocked. Items decrypted in memory.", "ok");
  } catch {
    account = null;
    renderPlain();
    log("Failed: invalid password or Secret Key.", "err");
  }
});
