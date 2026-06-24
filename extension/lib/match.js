// Shared site-matching for "on this site" suggestions and inline autofill.
// Imported by both the service worker (SUGGEST) and the popup so the two always
// agree. Matches by registrable domain (so subdomains of one site match each
// other) plus a small table of equivalent domains that share one login (the
// classic password-manager "equivalent domains" problem — e.g. signing into
// login.microsoftonline.com with an account saved under live.com).

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

// Registrable domain: last two labels. Good enough for .com/.ca/.net/.io/.nz
// etc.; imperfect for multi-level TLDs like .co.uk (treats it as co.uk), which
// is an acceptable trade-off here.
function registrable(host) {
  const parts = host.split(".");
  return parts.slice(-2).join(".");
}

// Domains that share a single sign-in. Each inner array is one equivalence
// group, compared by registrable domain.
const EQUIVALENT = [
  ["live.com", "microsoftonline.com", "microsoft.com", "outlook.com", "office.com", "office365.com", "msn.com", "hotmail.com", "skype.com", "windows.net", "azure.com", "xbox.com", "sharepoint.com"],
  ["google.com", "youtube.com", "gmail.com", "googlemail.com"],
  ["apple.com", "icloud.com", "me.com", "mac.com"],
  ["amazon.com", "amazon.ca", "amazon.co.uk", "aws.amazon.com"],
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
