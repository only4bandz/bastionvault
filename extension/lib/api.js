// Client for the zero-knowledge sync server, used from the service worker.
// Unlike the web app (which goes through a Vite dev proxy at /api), the
// extension talks to an absolute server URL and relies on host_permissions so
// the background fetch is not subject to CORS. The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function req(base, method, path, token, body) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res;
  try {
    res = await fetch(base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, "Cannot reach the Bastion server. Check the server URL in the extension options.");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? await res.json() : undefined;
}

/** Build an API bound to a given server base URL (e.g. http://127.0.0.1:7777). */
export function makeApi(base) {
  return {
    prelogin: (email) => req(base, "GET", `/accounts/${encodeURIComponent(email)}/prelogin`),
    login: (email, auth_secret) =>
      req(base, "POST", "/sessions", undefined, { email, auth_secret }).then((r) => r.token),
    logout: (token) => req(base, "DELETE", "/sessions", token),
    getVault: (token) => req(base, "GET", "/vault", token),
    putItem: (token, id, blob) => req(base, "PUT", `/vault/items/${encodeURIComponent(id)}`, token, { blob }),
    deleteItem: (token, id) => req(base, "DELETE", `/vault/items/${encodeURIComponent(id)}`, token),
  };
}
