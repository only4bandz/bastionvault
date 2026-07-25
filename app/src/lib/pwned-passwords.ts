import type { VaultItem } from "./types";

const RANGE_ENDPOINT = "https://api.pwnedpasswords.com/range/";
export const PWNED_REQUEST_TIMEOUT_MS = 10_000;
export const MAX_PWNED_RESPONSE_BYTES = 1024 * 1024;

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

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength &&
    /^[0-9]+$/.test(declaredLength) &&
    BigInt(declaredLength) > BigInt(maxBytes)
  ) {
    throw new Error("Breach service response exceeded the safe size limit.");
  }
  const reader = response.body?.getReader();
  if (!reader) throw new Error("Breach service returned an unreadable response.");
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new Error("Breach service response exceeded the safe size limit.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export async function fetchPwnedRange(
  prefix: string,
  signal?: AbortSignal,
  timeoutMs: number = PWNED_REQUEST_TIMEOUT_MS,
  maxBytes: number = MAX_PWNED_RESPONSE_BYTES
): Promise<Map<string, number>> {
  const controller = new AbortController();
  const abortFromCaller = () => controller.abort(signal?.reason);
  if (signal?.aborted) abortFromCaller();
  else signal?.addEventListener("abort", abortFromCaller, { once: true });
  const timeout = setTimeout(
    () => controller.abort(new DOMException("Breach service request timed out.", "TimeoutError")),
    timeoutMs
  );
  try {
    const response = await fetch(`${RANGE_ENDPOINT}${prefix}`, {
      headers: { "Add-Padding": "true" },
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      signal: controller.signal,
    });
    if (!response.ok) throw new Error(`Breach service returned HTTP ${response.status}.`);
    return parseRange(await readBoundedText(response, maxBytes));
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abortFromCaller);
  }
}

/**
 * Check one candidate password (e.g. a master password before vault creation)
 * through the same k-anonymous range API. Only the five-character SHA-1 prefix
 * leaves the browser. Returns the breach occurrence count (0 = not found).
 */
export async function checkPwnedPassword(
  password: string,
  signal?: AbortSignal
): Promise<number> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffixes = await fetchPwnedRange(prefix, signal);
  return suffixes.get(hash.slice(5)) ?? 0;
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
    const suffixes = await fetchPwnedRange(prefix, signal);
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
