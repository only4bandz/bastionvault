import { matchesSite } from "./match.js";

export function autofillPolicyError(item, tab, expectedTabId) {
  if (!Number.isInteger(expectedTabId) || !tab || tab.id !== expectedTabId) {
    return "The active tab changed. Reopen Bastion before filling.";
  }
  if (item?.type !== "login") return "Only login items can be filled.";

  let host;
  try {
    const url = new URL(tab.url);
    if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("unsupported protocol");
    host = url.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "Open a website before filling credentials.";
  }

  if (!matchesSite(item.url || item.title, host)) {
    return "This credential is not saved for the active website.";
  }
  return null;
}
