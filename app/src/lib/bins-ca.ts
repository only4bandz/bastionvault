// Local BIN/IIN table → issuer + debit/credit, so card detection works fully
// offline with no API dependency. Each entry is VERIFIED (not guessed): a wrong
// bank attribution is worse than none. Add entries as cards are confirmed.
import { BANKS, type Bank } from "./banks-ca";
import type { Scheme } from "./bin";

export interface BinSeed {
  bin: string; // 6–8 digit prefix
  bank: string; // bank id (see BANKS)
  type?: "debit" | "credit";
  scheme?: Scheme;
}

// Verified BIN prefixes. Longest-prefix wins, so 8-digit entries override 6-digit.
export const CA_BINS: BinSeed[] = [
  { bin: "450644", bank: "cibc", type: "debit", scheme: "visa" }, // verified
  // ── add the user's cards here (6-digit BIN · bank · debit/credit) ──
];

export interface LocalBin {
  bank: Bank;
  type?: "debit" | "credit";
  scheme?: Scheme;
}

/** Local issuer detection by longest matching BIN prefix. No network. */
export function detectBankLocal(bin: string): LocalBin | null {
  const n = bin.replace(/\D/g, "");
  if (n.length < 6) return null;
  let best: BinSeed | null = null;
  for (const s of CA_BINS) {
    if (n.startsWith(s.bin) && (!best || s.bin.length > best.bin.length)) best = s;
  }
  if (!best) return null;
  const bank = BANKS[best.bank];
  if (!bank) return null;
  return { bank, type: best.type, scheme: best.scheme };
}
