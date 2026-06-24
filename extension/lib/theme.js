// Theme: "system" (follow OS), "dark", or "light". Stored in chrome.storage.local
// (a non-secret preference). Applied by setting data-theme on <html>; tokens.css
// defines the dark default (:root) and the [data-theme="light"] override.

const mql = () => matchMedia("(prefers-color-scheme: light)");

export function applyTheme(theme) {
  const light = theme === "light" || (theme !== "dark" && mql().matches);
  document.documentElement.dataset.theme = light ? "light" : "dark";
}

export async function initTheme() {
  let theme = "system";
  try {
    theme = (await chrome.storage.local.get("theme")).theme || "system";
  } catch {
    /* storage unavailable */
  }
  applyTheme(theme);
  // Live-update while on "system" if the OS theme flips.
  mql().addEventListener?.("change", async () => {
    const t = (await chrome.storage.local.get("theme").catch(() => ({}))).theme || "system";
    if (t === "system") applyTheme("system");
  });
  return theme;
}
