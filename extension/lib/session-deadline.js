export const SESSION_ABSOLUTE_MS = 12 * 60 * 60 * 1000;

export function newAbsoluteSessionDeadline(now = Date.now()) {
  return now + SESSION_ABSOLUTE_MS;
}

export function boundedSessionExpiry(now, keepMinutes, absoluteExpiresAt) {
  if (
    !Number.isSafeInteger(now) ||
    !Number.isFinite(keepMinutes) ||
    keepMinutes <= 0 ||
    !Number.isSafeInteger(absoluteExpiresAt)
  ) {
    return null;
  }
  return Math.min(now + keepMinutes * 60_000, absoluteExpiresAt);
}

export function storedSessionDeadlines(stored, now = Date.now()) {
  if (!stored || typeof stored !== "object") return null;
  const absoluteExpiresAt = stored.absoluteExpiresAt ?? stored.expiresAt;
  if (
    !Number.isSafeInteger(now) ||
    !Number.isSafeInteger(stored.expiresAt) ||
    !Number.isSafeInteger(absoluteExpiresAt) ||
    stored.expiresAt > absoluteExpiresAt ||
    now > stored.expiresAt ||
    now > absoluteExpiresAt
  ) {
    return null;
  }
  return { expiresAt: stored.expiresAt, absoluteExpiresAt };
}
