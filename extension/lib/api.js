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
export const MAX_ERROR_BODY_BYTES = 4096;
/** How much raw server text is kept on the error, for debugging only. */
export const MAX_SERVER_DETAIL_CHARS = 200;
/** Maximum successful JSON response accepted from the sync server (80 MiB). */
export const MAX_SUCCESS_BODY_BYTES = 80 * 1024 * 1024;
const MAX_VAULT_ITEMS = 10_000;
const MAX_ITEM_ID_BYTES = 256;
const MAX_VAULT_BLOB_BYTES = 512 * 1024;
const MAX_VAULT_MANIFEST_BYTES = 8 * 1024 * 1024;

/**
 * Fixed, local message per status class. The server's response body is
 * ATTACKER-CONTROLLED from the extension's point of view (a malicious or
 * compromised server): it must never become UI text, where it could carry
 * arbitrary-length garbage or phishing copy ("re-enter your master password
 * at …"). Callers that need specifics branch on `error.status`.
 */
export function statusMessage(status) {
  if (status === 401) return "The server rejected the session or credentials.";
  if (status === 403) return "Mailbox verification is required or has expired.";
  if (status === 404) return "Not found on the server.";
  if (status === 409) return "The server reported a conflict with another change.";
  if (status === 413) return "The request is too large for the server.";
  if (status === 429) return "The server is rate-limiting requests. Try again shortly.";
  if (status >= 500) return "The server hit an internal error.";
  return `The server rejected the request (HTTP ${status}).`;
}

export const REQUEST_TIMEOUT_MS = 15_000;
export const API_PREFIX = "/v1";

export function isJsonMediaType(value) {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

function exactRecord(value, keys) {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function canonicalBase64Length(value) {
  if (
    typeof value !== "string" ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)
  ) {
    return null;
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

function exactBase64Bytes(value, decodedBytes) {
  return canonicalBase64Length(value) === decodedBytes;
}

function validEncryptedBlob(value, maxCiphertextBytes) {
  if (!exactRecord(value, ["v", "nonce", "ct"]) || value.v !== 1) return false;
  const ciphertextBytes = canonicalBase64Length(value.ct);
  return (
    ciphertextBytes !== null &&
    ciphertextBytes >= 16 &&
    ciphertextBytes <= maxCiphertextBytes &&
    exactBase64Bytes(value.nonce, 24)
  );
}

function validItemId(value) {
  return (
    value.length > 0 &&
    value.length <= MAX_ITEM_ID_BYTES &&
    /^[\x21-\x7e]+$/.test(value) &&
    !/[\\/ ?#]/.test(value)
  );
}

export function requireVaultResponse(value) {
  if (
    !exactRecord(value, ["items", "manifest", "revision"]) ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0 ||
    !value.items ||
    typeof value.items !== "object" ||
    Array.isArray(value.items)
  ) {
    throw new ApiError(200, "Server returned an invalid vault response.");
  }
  const items = Object.entries(value.items);
  if (
    items.length > MAX_VAULT_ITEMS ||
    items.some(
      ([id, blob]) =>
        !validItemId(id) || !validEncryptedBlob(blob, MAX_VAULT_BLOB_BYTES)
    ) ||
    (value.manifest !== null &&
      !validEncryptedBlob(value.manifest, MAX_VAULT_MANIFEST_BYTES))
  ) {
    throw new ApiError(200, "Server returned an invalid vault response.");
  }
  return value;
}

function validBastionId(value) {
  return typeof value === "string" && /^[A-Z2-7]{25}[AEIMQUY4]$/.test(value);
}

export function requireSendPublicResponse(value) {
  if (
    !exactRecord(value, ["enc_pub", "sig_pub", "key_version"]) ||
    value.key_version !== 1 ||
    !Array.isArray(value.enc_pub) ||
    value.enc_pub.length !== 32 ||
    !value.enc_pub.every(
      (byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255
    ) ||
    !Array.isArray(value.sig_pub) ||
    value.sig_pub.length !== 32 ||
    !value.sig_pub.every(
      (byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255
    )
  ) {
    throw new ApiError(200, "Server returned an invalid Send identity.");
  }
  return value;
}

export function requirePublishedIdentityResponse(value) {
  if (
    !exactRecord(value, ["bastion_id"]) ||
    !validBastionId(value.bastion_id)
  ) {
    throw new ApiError(200, "Server returned an invalid Send identity response.");
  }
  return { bastion_id: value.bastion_id };
}

export function requireWhoamiResponse(value) {
  if (
    !exactRecord(value, ["bastion_id", "public"]) ||
    !validBastionId(value.bastion_id)
  ) {
    throw new ApiError(200, "Server returned an invalid Send identity response.");
  }
  return {
    bastion_id: value.bastion_id,
    public: requireSendPublicResponse(value.public),
  };
}

export function requirePreloginResponse(value) {
  if (
    !exactRecord(value, ["salt", "kdf", "wrapped_vault_key"]) ||
    !exactBase64Bytes(value.salt, 16) ||
    !exactRecord(value.kdf, ["mem_kib", "iterations", "parallelism"]) ||
    !Number.isSafeInteger(value.kdf.mem_kib) ||
    value.kdf.mem_kib <= 0 ||
    !Number.isSafeInteger(value.kdf.iterations) ||
    value.kdf.iterations <= 0 ||
    !Number.isSafeInteger(value.kdf.parallelism) ||
    value.kdf.parallelism <= 0 ||
    !exactRecord(value.wrapped_vault_key, ["v", "nonce", "ct"]) ||
    value.wrapped_vault_key.v !== 1 ||
    !exactBase64Bytes(value.wrapped_vault_key.nonce, 24) ||
    !exactBase64Bytes(value.wrapped_vault_key.ct, 48)
  ) {
    throw new ApiError(200, "Server returned an invalid prelogin response.");
  }
  return value;
}

export function requireSessionTokenResponse(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(value, "token") ||
    typeof value.token !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.token)
  ) {
    throw new ApiError(200, "Server returned an invalid session response.");
  }
  return value.token;
}

export function requireRevisionResponse(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(value, "revision") ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0
  ) {
    throw new ApiError(200, "Server returned an invalid revision response.");
  }
  return { revision: value.revision };
}

/** Reads at most MAX_ERROR_BODY_BYTES of an error body — a hostile server
 * must not be able to balloon the worker's memory with a huge error page. */
export async function readErrorBody(res) {
  try {
    const reader = res.body?.getReader?.();
    if (!reader) return "";
    const decoder = new TextDecoder();
    let out = "";
    let bytesRead = 0;
    while (bytesRead < MAX_ERROR_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = MAX_ERROR_BODY_BYTES - bytesRead;
      const accepted = value.subarray(0, remaining);
      bytesRead += accepted.byteLength;
      out += decoder.decode(accepted, { stream: true });
      if (accepted.byteLength < value.byteLength) break;
    }
    reader.cancel().catch(() => {});
    out += decoder.decode();
    return out;
  } catch {
    return "";
  }
}

async function readJsonBody(res, maxBytes) {
  const declaredLength = res.headers.get("content-length");
  if (
    declaredLength &&
    /^[0-9]+$/.test(declaredLength) &&
    BigInt(declaredLength) > BigInt(maxBytes)
  ) {
    throw new ApiError(res.status, "Server response exceeded the safe size limit.");
  }
  const reader = res.body?.getReader?.();
  if (!reader) {
    throw new ApiError(res.status, "Server returned an unreadable JSON response.");
  }
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new ApiError(res.status, "Server response exceeded the safe size limit.");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(res.status, "Server returned invalid JSON.");
  }
}

async function req(
  base,
  method,
  path,
  token,
  body,
  timeoutMs,
  maxResponseBytes,
  responseKind = "json"
) {
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
      // The sync server is outside the extension trust boundary. Never let a
      // bearer token follow a redirect, attach ambient browser credentials,
      // populate an HTTP cache, or disclose the current page as a referrer.
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) {
      const text = await readErrorBody(res);
      throw new ApiError(
        res.status,
        statusMessage(res.status),
        text.slice(0, MAX_SERVER_DETAIL_CHARS)
      );
    }
    if (responseKind === "empty") return undefined;
    if (!isJsonMediaType(res.headers.get("content-type"))) {
      throw new ApiError(res.status, "Server returned a non-JSON response.");
    }
    return await readJsonBody(res, maxResponseBytes);
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
export function makeApi(
  base,
  { timeoutMs = REQUEST_TIMEOUT_MS, maxResponseBytes = MAX_SUCCESS_BODY_BYTES } = {}
) {
  const call = (method, path, token, body, responseKind = "json") =>
    req(
      base,
      method,
      API_PREFIX + path,
      token,
      body,
      timeoutMs,
      maxResponseBytes,
      responseKind
    );
  return {
    prelogin: (email) =>
      call("GET", `/accounts/${encodeURIComponent(email)}/prelogin`).then(
        requirePreloginResponse
      ),
    login: (email, auth_secret) =>
      call("POST", "/sessions", undefined, { email, auth_secret }).then(
        requireSessionTokenResponse
      ),
    logout: (token) => call("DELETE", "/sessions", token, undefined, "empty"),
    deleteAccount: (token, authSecret) =>
      call("DELETE", "/accounts", token, { auth_secret: authSecret }, "empty"),
    getVault: (token) =>
      call("GET", "/vault", token).then(requireVaultResponse),
    getVaultRevision: (token) =>
      call("GET", "/vault/revision", token).then(requireRevisionResponse),
    mutateVault: (token, expectedRevision, operations, manifest) =>
      call("PUT", "/vault/transaction", token, {
        expected_revision: expectedRevision,
        operations,
        manifest,
      }).then(requireRevisionResponse),

    // ── Bastion Send ──
    publishIdentity: (token, publicIdentity) =>
      call("PUT", "/send/identity", token, publicIdentity).then(
        requirePublishedIdentityResponse
      ),
    whoami: (token) =>
      call("GET", "/send/whoami", token).then(requireWhoamiResponse),
    directory: (token, bastionId) =>
      call("GET", `/send/directory/${encodeURIComponent(bastionId)}`, token).then(
        requireSendPublicResponse
      ),
    sendBlob: (token, body) => call("POST", "/send", token, body, "empty"),
    inbox: (token) => call("GET", "/send/inbox", token),
    inboxDelete: (token, messageId) =>
      call("DELETE", `/send/inbox/${encodeURIComponent(messageId)}`, token, undefined, "empty"),
  };
}
