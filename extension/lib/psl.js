// Public Suffix List algorithm (https://publicsuffix.org/list/) over the full
// list in psl-data.js. Used to compute the registrable domain (eTLD+1) so that
// site matching never collapses different owners on a shared suffix
// (a.github.io vs b.github.io, *.vercel.app, foo.co.uk vs bar.co.uk, …).
import { PSL_NORMAL, PSL_WILDCARD, PSL_EXCEPTION } from "./psl-data.js";

const RULES = new Set(PSL_NORMAL.split("\n"));
const WILDCARDS = new Set(PSL_WILDCARD.split("\n")); // bases X of "*.X" rules
const EXCEPTIONS = new Set(PSL_EXCEPTION.split("\n")); // Y of "!Y" rules

/** The public suffix (eTLD) of a host, per the PSL matching algorithm. */
export function publicSuffix(host) {
  const labels = host.split(".");
  // Exception rules win: "!Y" → the public suffix is Y minus its first label.
  for (let i = 0; i < labels.length; i++) {
    if (EXCEPTIONS.has(labels.slice(i).join("."))) return labels.slice(i + 1).join(".");
  }
  // Otherwise the longest matching normal or wildcard rule (scan longest first).
  for (let i = 0; i < labels.length; i++) {
    const candidate = labels.slice(i).join(".");
    if (RULES.has(candidate)) return candidate;
    if (i < labels.length - 1 && WILDCARDS.has(labels.slice(i + 1).join("."))) return candidate;
  }
  return labels[labels.length - 1]; // implicit "*" rule: the rightmost label
}

/**
 * Registrable domain (eTLD+1): the public suffix plus one more label. Returns
 * null when the host is itself a public suffix (no registrable part exists).
 */
export function registrableDomain(host) {
  const ps = publicSuffix(host);
  if (host === ps) return null;
  const labels = host.split(".");
  const psLen = ps.split(".").length;
  if (labels.length <= psLen) return null;
  return labels.slice(labels.length - psLen - 1).join(".");
}
