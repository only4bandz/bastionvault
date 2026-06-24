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

// Public suffixes where each subdomain is a DIFFERENT owner. Treating these as
// the registrable domain (last two labels) would collapse e.g. a.github.io and
// b.github.io into one site and leak credentials across tenants. This is a
// curated subset of the Public Suffix List covering common multi-level ccTLDs
// and shared-hosting platforms; swap in a full PSL for completeness.
const PUBLIC_SUFFIXES = new Set([
  // multi-level ccTLDs
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk",
  "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp",
  "co.nz", "net.nz", "org.nz", "govt.nz",
  "com.au", "net.au", "org.au", "gov.au", "edu.au", "asn.au", "id.au",
  "co.za", "org.za", "co.in", "net.in", "org.in", "co.kr", "or.kr",
  "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.sg", "com.hk", "com.tw", "com.ua", "co.il",
  // shared-hosting / app / PaaS platforms (subdomain = separate owner)
  "github.io", "github.dev", "gitlab.io", "pages.dev", "workers.dev", "r2.dev",
  "vercel.app", "vercel.sh", "netlify.app", "netlify.com", "web.app", "firebaseapp.com",
  "herokuapp.com", "herokudns.com", "azurewebsites.net", "cloudapp.azure.com",
  "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "elasticbeanstalk.com",
  "fly.dev", "onrender.com", "render.com", "railway.app", "replit.app", "repl.co",
  "glitch.me", "surge.sh", "now.sh", "appspot.com", "translate.goog",
  "blogspot.com", "wordpress.com", "wixsite.com", "weebly.com", "squarespace.com",
  "ngrok.io", "ngrok-free.app", "trycloudflare.com", "githubusercontent.com",
]);

// Registrable domain (eTLD+1). Find the LONGEST tail of `host` that is a listed
// public suffix (handles multi-level suffixes like s3.amazonaws.com or co.uk),
// then take it plus the one label before it. With no listed suffix, fall back
// to the last two labels (single-label TLDs like .com/.io/.ca).
function registrable(host) {
  const parts = host.split(".");
  for (let i = 0; i + 1 < parts.length; i++) {
    const suffix = parts.slice(i).join(".");
    if (PUBLIC_SUFFIXES.has(suffix)) {
      return i === 0 ? host : parts.slice(i - 1).join(".");
    }
  }
  return parts.slice(-2).join(".");
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
