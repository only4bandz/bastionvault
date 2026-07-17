import { matchesSite } from "./match.js";
import { registrableDomain } from "./psl.js";

const INSECURE_HTTP_ERROR = "Credentials are never released to insecure HTTP pages.";
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

export function credentialPageError(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return "Open a website before filling credentials.";
  }

  if (url.protocol === "https:") return null;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname.toLowerCase())) return null;
  if (url.protocol === "http:") return INSECURE_HTTP_ERROR;
  return "Open a website before filling credentials.";
}

/**
 * Inline autofill (SUGGEST/CREDS) runs inside the sender FRAME, which may be
 * an iframe. Releasing bank.com credentials into a bank.com iframe embedded by
 * evil.example is a UI-redress trap: the user believes they are on the top
 * page. Rule (Bitwarden's model): the frame may receive suggestions/credentials
 * only when its registrable site matches the top-level page's registrable site.
 * Returns null when allowed, an error string otherwise. Fails closed when the
 * top URL is unavailable.
 */
export function frameAutofillError(frameUrl, tabUrl) {
  let frameHost;
  let tabHost;
  try {
    frameHost = new URL(frameUrl).hostname.toLowerCase();
    tabHost = new URL(tabUrl).hostname.toLowerCase();
  } catch {
    return "Autofill is unavailable in this frame.";
  }
  if (!frameHost || !tabHost) return "Autofill is unavailable in this frame.";
  if (registrableDomain(frameHost) !== registrableDomain(tabHost)) {
    return "Autofill is disabled inside third-party frames.";
  }
  return null;
}

export function autofillPolicyError(item, tab, expectedTabId) {
  if (!Number.isInteger(expectedTabId) || !tab || tab.id !== expectedTabId) {
    return "The active tab changed. Reopen Bastion before filling.";
  }
  if (item?.type !== "login") return "Only login items can be filled.";

  const pageError = credentialPageError(tab.url);
  if (pageError) return pageError;

  let host;
  try {
    const url = new URL(tab.url);
    host = url.hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "Open a website before filling credentials.";
  }

  if (!matchesSite(item.url || item.title, host)) {
    return "This credential is not saved for the active website.";
  }
  return null;
}

export function validatedAutofillTarget(item, tab, expectedTabId, injectionResults) {
  const probe = Array.isArray(injectionResults) && injectionResults.length === 1 ? injectionResults[0] : null;
  if (
    !probe ||
    probe.frameId !== 0 ||
    typeof probe.documentId !== "string" ||
    !probe.documentId ||
    typeof probe.result !== "string"
  ) {
    throw new Error("The active page could not be verified. Reopen Bastion before filling.");
  }

  const policyError = autofillPolicyError(item, { id: tab?.id, url: probe.result }, expectedTabId);
  if (policyError) throw new Error(policyError);
  return { tabId: tab.id, documentIds: [probe.documentId] };
}
