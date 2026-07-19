import type { VaultItem } from "./types";

const RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";

export interface PwnedPasswordFinding {
  item: VaultItem;
  occurrences: number;
}

async function sha1Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function parseRange(body: string): Map<string, number> {
  const suffixes = new Map<string, number>();
  for (const line of body.split(/\r?\n/)) {
    const [suffix, rawCount] = line.trim().split(":");
    if (!/^[0-9A-F]{35}$/i.test(suffix ?? "")) continue;
    const count = Number(rawCount);
    if (Number.isSafeInteger(count) && count > 0) suffixes.set(suffix.toUpperCase(), count);
  }
  return suffixes;
}

/**
 * Manually check distinct vault passwords through HIBP's k-anonymous range API.
 * Only a five-character SHA-1 prefix leaves the browser. Results remain in RAM.
 */
export async function scanPwnedPasswords(
  items: VaultItem[],
  signal?: AbortSignal
): Promise<PwnedPasswordFinding[]> {
  const passwordItems = new Map<string, VaultItem[]>();
  for (const item of items) {
    if (item.type !== "login" || !item.password || item.deletedAt !== undefined) continue;
    const matches = passwordItems.get(item.password) ?? [];
    matches.push(item);
    passwordItems.set(item.password, matches);
  }

  const hashes = await Promise.all(
    [...passwordItems.keys()].map(async (password) => ({ password, hash: await sha1Hex(password) }))
  );
  const byPrefix = new Map<string, { password: string; hash: string }[]>();
  for (const entry of hashes) {
    const prefix = entry.hash.slice(0, 5);
    const entries = byPrefix.get(prefix) ?? [];
    entries.push(entry);
    byPrefix.set(prefix, entries);
  }

  const findings: PwnedPasswordFinding[] = [];
  for (const [prefix, entries] of byPrefix) {
    const response = await fetch(`${RANGE_ENDPOINT}${prefix}`, {
      headers: { "Add-Padding": "true" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal,
    });
    if (!response.ok) throw new Error(`Breach service returned HTTP ${response.status}.`);
    const suffixes = parseRange(await response.text());
    for (const entry of entries) {
      const occurrences = suffixes.get(entry.hash.slice(5)) ?? 0;
      if (occurrences === 0) continue;
      for (const item of passwordItems.get(entry.password) ?? []) {
        findings.push({ item, occurrences });
      }
    }
  }
  return findings.sort(
    (left, right) => right.occurrences - left.occurrences || left.item.title.localeCompare(right.item.title)
  );
}
