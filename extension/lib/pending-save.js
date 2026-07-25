export const PENDING_TTL_MS = 10 * 60 * 1000;

export function makePendingSave(value, now = Date.now()) {
  return { ...value, stagedAt: now };
}

export function pendingSaveExpiresAt(record) {
  return record.stagedAt + PENDING_TTL_MS;
}

export function pendingSaveIsExpired(record, now = Date.now()) {
  return (
    !record ||
    typeof record !== "object" ||
    !Number.isFinite(record.stagedAt) ||
    record.stagedAt > now ||
    now > pendingSaveExpiresAt(record)
  );
}
