// Card network detection (local) + issuer (bank) lookup from the BIN/IIN.
export type Scheme = "visa" | "mastercard" | "amex" | "discover" | "unknown";

/** Detect the card network locally from the leading digits (no network call). */
export function detectScheme(num: string): Scheme {
  const n = num.replace(/\D/g, "");
  if (/^4/.test(n)) return "visa";
  if (/^(5[1-5]|2[2-7])/.test(n)) return "mastercard";
  if (/^3[47]/.test(n)) return "amex";
  if (/^6(?:011|5|4[4-9]|22)/.test(n)) return "discover";
  return "unknown";
}

export interface BinInfo {
  scheme?: Scheme;
  bankName?: string;
  bankDomain?: string;
}

const cache = new Map<string, BinInfo | null>();

// Map common issuers (Canada-
// focused, since that's the primary use) to a domain so we can show their logo.
const BANK_DOMAINS: [RegExp, string][] = [
  [/imperial bank of commerce|cibc/i, "cibc.com"],
  [/toronto.?dominion|\btd\b/i, "td.com"],
  [/royal bank of canada|\brbc\b/i, "rbc.com"],
  [/bank of montreal|\bbmo\b/i, "bmo.com"],
  [/nova scotia|scotiabank/i, "scotiabank.com"],
  [/national bank of canada|banque nationale/i, "nbc.ca"],
  [/desjardins/i, "desjardins.com"],
  [/tangerine/i, "tangerine.ca"],
  [/canadian tire/i, "canadiantire.ca"],
  [/simplii/i, "simplii.com"],
  [/capital one/i, "capitalone.com"],
  [/american express|amex/i, "americanexpress.com"],
  [/\bchase\b|jpmorgan/i, "chase.com"],
  [/wells fargo/i, "wellsfargo.com"],
  [/citibank|citigroup|\bciti\b/i, "citi.com"],
  [/bank of america/i, "bankofamerica.com"],
  [/\bhsbc\b/i, "hsbc.com"],
  [/barclays/i, "barclays.co.uk"],
  [/revolut/i, "revolut.com"],
  [/\bwise\b|transferwise/i, "wise.com"],
  [/paypal/i, "paypal.com"],
  [/monzo/i, "monzo.com"],
  [/\bn26\b/i, "n26.com"],
];

function domainForBankName(name?: string): string | undefined {
  if (!name) return undefined;
  for (const [re, domain] of BANK_DOMAINS) if (re.test(name)) return domain;
  return undefined;
}

/**
 * Look up the issuing bank for a BIN via the Bastion server's cached `/api/bin`
 * endpoint (each BIN hits the upstream service at most once, server-side). The
 * full card number is never sent — only the BIN. Returns null on miss so callers
 * fall back to the local scheme badge.
 */
export async function lookupBin(bin: string): Promise<BinInfo | null> {
  const key = bin.replace(/\D/g, "").slice(0, 8);
  if (key.length < 6) return null;
  if (cache.has(key)) return cache.get(key) ?? null;
  try {
    const res = await fetch(`/api/bin/${key}`);
    if (!res.ok) return null;
    const j = (await res.json()) as { scheme?: string; bank_name?: string };
    if (!j.scheme && !j.bank_name) return null; // upstream miss — retry later (cheap, hits server cache)
    const info: BinInfo = {
      scheme: (j.scheme as Scheme) || undefined,
      bankName: j.bank_name || undefined,
      bankDomain: domainForBankName(j.bank_name),
    };
    cache.set(key, info);
    return info;
  } catch {
    return null;
  }
}
