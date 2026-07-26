export const MAX_ACCOUNT_ID_CHARS = 254;

/**
 * Canonical account identity shared with the server and main app.
 *
 * Account ids are ASCII mailbox-shaped strings. Lowercasing the complete id is
 * intentional: it prevents case variants from selecting different vaults,
 * authentication buckets, sessions, or rollback-checkpoint scopes.
 */
export function canonicalAccountId(value) {
  if (typeof value !== "string") throw new Error("Invalid account id.");
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
    throw new Error("Invalid account id.");
  }
  return trimmed.toLowerCase();
}
