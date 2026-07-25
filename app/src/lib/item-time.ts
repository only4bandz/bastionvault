const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;
/** Average civil month and year, so buckets stay stable across month lengths. */
const MONTH = Math.round((365.2425 * DAY) / 12);
const YEAR = Math.round(365.2425 * DAY);

/**
 * Compact relative time for a validated vault-item timestamp.
 *
 * Buckets coarsen with distance. Past a couple of weeks, "985d ago" carries no
 * more information than "2y ago" but makes the reader do arithmetic — and this
 * string is what tells someone a password has gone stale, so it has to be
 * legible at a glance. Days are kept up to two weeks, where the exact count
 * still means something.
 */
export function relativeItemTime(timestamp: number, now: number): string {
  if (!Number.isFinite(timestamp) || !Number.isFinite(now)) return "unknown";
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < MINUTE) return "just now";
  if (seconds < HOUR) return `${Math.floor(seconds / MINUTE)}m ago`;
  if (seconds < DAY) return `${Math.floor(seconds / HOUR)}h ago`;
  if (seconds < 2 * WEEK) return `${Math.floor(seconds / DAY)}d ago`;
  if (seconds < 2 * MONTH) return `${Math.floor(seconds / WEEK)}w ago`;
  if (seconds < YEAR) return `${Math.floor(seconds / MONTH)}mo ago`;
  return `${Math.floor(seconds / YEAR)}y ago`;
}
