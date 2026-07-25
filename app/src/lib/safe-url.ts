/**
 * Return a normalized website destination only when navigation is explicitly
 * safe. Saved values remain copyable even when this rejects them.
 */
/**
 * Hosts browsers treat as a secure context despite the `http:` scheme, because
 * the traffic never leaves the machine. Flagging these would be pure noise.
 */
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]", "::1"]);

/**
 * True when the saved website would carry credentials over cleartext HTTP.
 *
 * A vault entry is a standing instruction to type a password into a specific
 * site. If that site is `http://`, every autofill and every manual paste puts
 * the password on the wire in the clear, readable by anything between the user
 * and the server — and the user has no way to notice from the vault list.
 * `safeWebsiteUrl` deliberately still accepts these (the link works, the value
 * stays copyable); this is the signal the UI needs to say so out loud.
 */
export function isInsecureWebsiteUrl(raw: string | undefined): boolean {
  const href = safeWebsiteUrl(raw);
  if (href === null) return false;
  const url = new URL(href);
  return url.protocol === "http:" && !LOCAL_HOSTS.has(url.hostname.toLowerCase());
}

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
