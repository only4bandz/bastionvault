// Options page: configure the sync server URL. The URL is NOT a secret, so it
// may live in chrome.storage. For a non-localhost server we also request the
// matching host permission (declared as optional) so the worker can reach it.

import { initTheme, applyTheme } from "./lib/theme.js";
import { DEFAULT_SERVER, normalizeServerUrl } from "./lib/server-url.js";
import { staleServerOrigins } from "./lib/permission-policy.js";

const input = document.getElementById("server");
const saved = document.getElementById("saved");
const permnote = document.getElementById("permnote");
const theme = document.getElementById("theme");

const keep = document.getElementById("keep");
const DEFAULT_KEEP_MINUTES = 60;

(async () => {
  const current = await initTheme();
  theme.value = current;
  const { serverUrl, keepUnlockMinutes } = await chrome.storage.local.get(["serverUrl", "keepUnlockMinutes"]);
  input.value = serverUrl || DEFAULT_SERVER;
  keep.value = String(keepUnlockMinutes || DEFAULT_KEEP_MINUTES);
})();

// Live preview while choosing (persisted on Save).
theme.addEventListener("change", () => applyTheme(theme.value));

document.getElementById("save").addEventListener("click", async () => {
  saved.textContent = "";
  permnote.textContent = "";
  let server;
  try {
    server = normalizeServerUrl(input.value);
  } catch (error) {
    permnote.style.color = "var(--danger)";
    permnote.textContent = error instanceof Error ? error.message : "Invalid server URL.";
    return;
  }

  const grantedBefore = await chrome.permissions.getAll().catch(() => null);
  if (!grantedBefore) {
    permnote.style.color = "var(--danger)";
    permnote.textContent = "Could not verify the extension's server permissions. Nothing was saved.";
    return;
  }

  // localhost / 127.0.0.1 are covered by the static host_permissions; any other
  // host needs an explicit grant from the optional permissions.
  const retainedPattern = server.hasBuiltInPermission ? null : server.permissionPattern;
  const retainedWasAlreadyGranted =
    retainedPattern !== null && grantedBefore.origins?.includes(retainedPattern);
  if (!server.hasBuiltInPermission) {
    const granted = await chrome.permissions
      .request({ origins: [server.permissionPattern] })
      .catch(() => false);
    if (!granted) {
      permnote.style.color = "var(--danger)";
      permnote.textContent = `Permission to reach ${server.permissionPattern} was denied — the extension can't contact that server.`;
      return;
    }
  }

  const staleOrigins = staleServerOrigins(grantedBefore.origins, retainedPattern);
  if (staleOrigins.length > 0) {
    const removed = await chrome.permissions
      .remove({ origins: staleOrigins })
      .catch(() => false);
    if (!removed) {
      if (retainedPattern && !retainedWasAlreadyGranted) {
        await chrome.permissions.remove({ origins: [retainedPattern] }).catch(() => false);
      }
      permnote.style.color = "var(--danger)";
      permnote.textContent = "Could not revoke access to the previous server. Nothing was saved.";
      return;
    }
  }

  await chrome.storage.local.set({
    serverUrl: server.url,
    keepUnlockMinutes: Number(keep.value),
    theme: theme.value,
  });
  applyTheme(theme.value);
  saved.textContent = "Saved ✓";
  permnote.style.color = "var(--muted)";
  const label = keep.selectedOptions[0]?.textContent || `${keep.value} min`;
  permnote.textContent = `Bastion will sync with ${server.url}. Keeps unlocked for ${label}.`;
});
