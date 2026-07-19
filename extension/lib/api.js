// Client for the zero-knowledge sync server, used from the service worker.
// Unlike the web app (which goes through a Vite dev proxy at /api), the
// extension talks to an absolute server URL and relies on host_permissions so
// the background fetch is not subject to CORS. The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.

export class ApiError extends Error {
  constructor(status, message, serverDetail = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    /** Capped raw server text, for debugging only — never rendered in UI. */
    this.serverDetail = serverDetail;
  }
}

/** Longest server error body we bother reading (anti memory-DoS). */
export const MAX_ERROR_BODY_CHARS = 4096;
/** How much raw server text is kept on the error, for debugging only. */
export const MAX_SERVER_DETAIL_CHARS = 200;

/**
 * Fixed, local message per status class. The server's response body is
 * ATTACKER-CONTROLLED from the extension's point of view (a malicious or
 * compromised server): it must never become UI text, where it could carry
 * arbitrary-length garbage or phishing copy ("re-enter your master password
 * at …"). Callers that need specifics branch on `error.status`.
 */
export function statusMessage(status) {
  if (status === 401) return "The server rejected the session or credentials.";
  if (status === 404) return "Not found on the server.";
  if (status === 409) return "The server reported a conflict with another change.";
  if (status === 413) return "The request is too large for the server.";
  if (status === 429) return "The server is rate-limiting requests. Try again shortly.";
  if (status >= 500) return "The server hit an internal error.";
  return `The server rejected the request (HTTP ${status}).`;
}

export const REQUEST_TIMEOUT_MS = 15_000;
export const API_PREFIX = "/v1";

/** Reads at most MAX_ERROR_BODY_CHARS of an error body — a hostile server
 * must not be able to balloon the worker's memory with a huge error page. */
async function readErrorBody(res) {
  try {
    const reader = res.body?.getReader?.();
    if (!reader) return ((await res.text()) || "").slice(0, MAX_ERROR_BODY_CHARS);
    const decoder = new TextDecoder();
    let out = "";
    while (out.length < MAX_ERROR_BODY_CHARS) {
      const { done, value } = await reader.read();
      if (done) break;
      out += decoder.decode(value, { stream: true });
    }
    reader.cancel().catch(() => {});
    return out.slice(0, MAX_ERROR_BODY_CHARS);
  } catch {
    return "";
  }
}

async function req(base, method, path, token, body, timeoutMs) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(base + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    if (!res.ok) {
      const text = await readErrorBody(res);
      throw new ApiError(
        res.status,
        statusMessage(res.status),
        text.slice(0, MAX_SERVER_DETAIL_CHARS)
      );
    }
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return undefined;
    try {
      return await res.json();
    } catch {
      throw new ApiError(res.status, "Server returned invalid JSON.");
    }
  } catch (error) {
    if (controller.signal.aborted) {
      throw new ApiError(0, "Server request timed out. The result is unknown; refresh before retrying.");
    }
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      0,
      "Cannot reach the Bastion server. Check the server URL in the extension options."
    );
  } finally {
    clearTimeout(timer);
  }
}

/** Build an API bound to a given server base URL (e.g. http://127.0.0.1:7777). */
export function makeApi(base, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const call = (method, path, token, body) =>
    req(base, method, API_PREFIX + path, token, body, timeoutMs);
  return {
    prelogin: (email) => call("GET", `/accounts/${encodeURIComponent(email)}/prelogin`),
    login: (email, auth_secret) =>
      call("POST", "/sessions", undefined, { email, auth_secret }).then((r) => r.token),
    logout: (token) => call("DELETE", "/sessions", token),
    deleteAccount: (token, authSecret) =>
      call("DELETE", "/accounts", token, { auth_secret: authSecret }),
    getVault: (token) => call("GET", "/vault", token),
    getVaultRevision: (token) => call("GET", "/vault/revision", token),
    mutateVault: (token, expectedRevision, operations, manifest) =>
      call("PUT", "/vault/transaction", token, {
        expected_revision: expectedRevision,
        operations,
        manifest,
      }),

    // ── Bastion Send ──
    publishIdentity: (token, publicIdentity) =>
      call("PUT", "/send/identity", token, publicIdentity),
    whoami: (token) => call("GET", "/send/whoami", token),
    directory: (token, bastionId) =>
      call("GET", `/send/directory/${encodeURIComponent(bastionId)}`, token),
    sendBlob: (token, body) => call("POST", "/send", token, body),
    inbox: (token) => call("GET", "/send/inbox", token),
    inboxDelete: (token, messageId) =>
      call("DELETE", `/send/inbox/${encodeURIComponent(messageId)}`, token),
  };
}
