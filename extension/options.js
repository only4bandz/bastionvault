// Options page: configure the sync server URL. The URL is NOT a secret, so it
// may live in chrome.storage. For a non-localhost server we also request the
// matching host permission (declared as optional) so the worker can reach it.

const DEFAULT_SERVER = "http://127.0.0.1:7777";
const input = document.getElementById("server");
const saved = document.getElementById("saved");
const permnote = document.getElementById("permnote");

function originPattern(url) {
  try {
    const u = new URL(url);
    return `${u.protocol}//${u.host}/*`;
  } catch {
    return null;
  }
}

const isBuiltin = (url) => {
  try {
    const h = new URL(url).hostname;
    return h === "localhost" || h === "127.0.0.1";
  } catch {
    return false;
  }
};

const keep = document.getElementById("keep");
const DEFAULT_KEEP_MINUTES = 60;

(async () => {
  const { serverUrl, keepUnlockMinutes } = await chrome.storage.local.get(["serverUrl", "keepUnlockMinutes"]);
  input.value = serverUrl || DEFAULT_SERVER;
  keep.value = String(keepUnlockMinutes || DEFAULT_KEEP_MINUTES);
})();

document.getElementById("save").addEventListener("click", async () => {
  saved.textContent = "";
  permnote.textContent = "";
  const url = input.value.trim().replace(/\/+$/, "");
  const pattern = originPattern(url);
  if (!pattern) {
    permnote.style.color = "var(--danger)";
    permnote.textContent = "That doesn't look like a valid URL.";
    return;
  }

  // localhost / 127.0.0.1 are covered by the static host_permissions; any other
  // host needs an explicit grant from the optional permissions.
  if (!isBuiltin(url)) {
    const granted = await chrome.permissions.request({ origins: [pattern] }).catch(() => false);
    if (!granted) {
      permnote.style.color = "var(--danger)";
      permnote.textContent = `Permission to reach ${pattern} was denied — the extension can't contact that server.`;
      return;
    }
  }

  await chrome.storage.local.set({ serverUrl: url, keepUnlockMinutes: Number(keep.value) });
  saved.textContent = "Saved ✓";
  permnote.style.color = "var(--muted)";
  const label = keep.selectedOptions[0]?.textContent || `${keep.value} min`;
  permnote.textContent = `Bastion will sync with ${url}. Keeps unlocked for ${label}.`;
});
