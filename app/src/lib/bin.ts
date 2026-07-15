// Card network detection (local) + issuer (bank) lookup from the BIN/IIN.
import { detectBankLocal } from "./bins-ca";

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
  cardType?: string; // "debit" | "credit"
}

/**
 * Look up an issuing bank exclusively from the bundled local table. Unknown
 * BINs return `null`; no part of a card number leaves the browser.
 */
export async function lookupBin(bin: string): Promise<BinInfo | null> {
  const key = bin.replace(/\D/g, "").slice(0, 8);
  if (key.length < 6) return null;

  const local = detectBankLocal(key);
  if (local) {
    const scheme = local.scheme ?? (detectScheme(key) === "unknown" ? undefined : detectScheme(key));
    return { scheme, bankName: local.bank.name, bankDomain: local.bank.domain, cardType: local.type };
  }
  return null;
}
