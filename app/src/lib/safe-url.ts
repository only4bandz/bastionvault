/**
 * Return a normalized website destination only when navigation is explicitly
 * safe. Saved values remain copyable even when this rejects them.
 */
export function safeWebsiteUrl(raw: string | undefined): string | null {
  const value = raw?.trim();
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    if (url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}
