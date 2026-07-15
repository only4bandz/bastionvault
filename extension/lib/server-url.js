export const DEFAULT_SERVER = "http://127.0.0.1:7777";

function isLocalHttp(url) {
  return (
    url.protocol === "http:" &&
    (url.hostname === "localhost" || url.hostname === "127.0.0.1")
  );
}

/** Validate and canonicalize the extension's sync-server trust boundary. */
export function normalizeServerUrl(raw) {
  let url;
  try {
    url = new URL(String(raw ?? "").trim());
  } catch {
    throw new Error("Enter a valid absolute server URL.");
  }

  if (url.username || url.password) {
    throw new Error("Server URLs must not contain credentials.");
  }
  if (url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new Error("Server URLs must contain only an origin, without a path, query, or fragment.");
  }
  if (url.protocol !== "https:" && !isLocalHttp(url)) {
    throw new Error("Remote servers must use HTTPS. Plain HTTP is allowed only on localhost.");
  }

  const normalized = url.origin;
  return {
    url: normalized,
    permissionPattern: `${normalized}/*`,
    hasBuiltInPermission: isLocalHttp(url),
  };
}
