export const MAX_ACCOUNT_ID_CHARS = 254;

/**
 * Canonical account identity shared with the server and browser extension.
 * Validate ASCII before lowercasing so Unicode case folding cannot turn a
 * confusable character into a different accepted account.
 */
export function canonicalAccountId(value: string): string {
  const trimmed = value.trim();
  const separator = trimmed.indexOf("@");
  if (
    trimmed.length === 0 ||
    trimmed.length > MAX_ACCOUNT_ID_CHARS ||
    !/^[\x21-\x7e]+$/.test(trimmed) ||
    separator <= 0 ||
    separator === trimmed.length - 1 ||
    trimmed.indexOf("@", separator + 1) !== -1
  ) {
    throw new Error("Invalid email address.");
  }
  return trimmed.toLowerCase();
}
