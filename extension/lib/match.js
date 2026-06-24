// Shared site-matching for "on this site" suggestions and inline autofill.
// Imported by both the service worker (SUGGEST) and the popup so the two always
// agree. Matches by registrable domain (eTLD+1 via the full Public Suffix List,
// so subdomains of one site match each other but different owners on a shared
// suffix do not) plus a small table of equivalent domains that share one login
// (the classic "equivalent domains" problem — e.g. signing into
// login.microsoftonline.com with an account saved under live.com).
import { registrableDomain } from "./psl.js";

/** Best-effort hostname from a URL or a bare "host/path" string. */
export function domainOf(value) {
  const c = (value || "").trim();
  if (!c.includes(".")) return null;
  let h = c;
  try {
    h = /^https?:\/\//i.test(c) ? new URL(c).hostname : c.split("/")[0];
  } catch {
    h = c.split("/")[0];
  }
  h = h.toLowerCase().replace(/^www\./, "");
  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(h) ? h : null;
}

// Registrable domain (eTLD+1) via the full PSL. Falls back to the host itself
// when it's a bare public suffix (so two identical public-suffix hosts still
// compare equal, but different owners under one suffix do not).
function registrable(host) {
  return registrableDomain(host) || host;
}

// Domains that share a single sign-in. Each inner array is one equivalence
// group, compared by registrable domain.
const EQUIVALENT = [
  ["live.com", "microsoftonline.com", "microsoft.com", "outlook.com", "office.com", "office365.com", "msn.com", "hotmail.com", "skype.com", "windows.net", "azure.com", "xbox.com", "sharepoint.com"],
  ["google.com", "youtube.com", "gmail.com", "googlemail.com"],
  ["apple.com", "icloud.com", "me.com", "mac.com"],
  ["amazon.com", "amazon.ca", "amazon.co.uk"], // NB: not aws.amazon.com — different auth boundary
  ["facebook.com", "fb.com", "meta.com", "instagram.com", "messenger.com"],
];

function groupOf(reg) {
  return EQUIVALENT.find((g) => g.includes(reg)) || null;
}

/** True if an item saved for `a` should be offered on a page at `b`. */
export function matchesSite(a, b) {
  const da = domainOf(a);
  const db = domainOf(b);
  if (!da || !db) return false;
  const ra = registrable(da);
  const rb = registrable(db);
  if (ra === rb) return true;
  const g = groupOf(ra);
  return !!g && g.includes(rb);
}
