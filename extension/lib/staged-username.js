export const STAGED_USERNAME_TTL_MS = 5 * 60 * 1000;

export function makeStagedUsername(username, host, now = Date.now()) {
  const value = (username || "").trim();
  if (!value || !host) return null;
  return { username: value, host, stagedAt: now };
}

export function stagedUsernameFor(record, host, now = Date.now()) {
  if (
    !record ||
    typeof record !== "object" ||
    typeof record.username !== "string" ||
    typeof record.host !== "string" ||
    typeof record.stagedAt !== "number" ||
    record.host !== host ||
    now - record.stagedAt < 0 ||
    now - record.stagedAt > STAGED_USERNAME_TTL_MS
  ) {
    return "";
  }
  return record.username;
}
