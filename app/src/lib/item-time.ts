/** Compact relative time for a validated vault-item timestamp. */
export function relativeItemTime(timestamp: number, now: number): string {
  if (!Number.isFinite(timestamp) || !Number.isFinite(now)) return "unknown";
  const seconds = Math.max(0, Math.floor((now - timestamp) / 1000));
  if (seconds < 60) return "just now";
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86_400)}d ago`;
}
