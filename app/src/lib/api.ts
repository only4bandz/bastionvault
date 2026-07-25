// Client for the zero-knowledge sync server. In dev, requests go through the
// Vite proxy (/api -> http://127.0.0.1:7777). The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.
const BASE = "/api/v1";
const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_ERROR_BODY_CHARS = 4096;
export const MAX_SERVER_DETAIL_CHARS = 200;
export const MAX_SUCCESS_BODY_BYTES = 80 * 1024 * 1024;

export interface Blob {
  v: number;
  nonce: string;
  ct: string;
}
export interface Registration {
  version: number;
  salt: string;
  kdf: { mem_kib: number; iterations: number; parallelism: number };
  wrapped_vault_key: Blob;
  auth_secret: string;
}
export interface Prelogin {
  salt: string;
  kdf: Registration["kdf"];
  wrapped_vault_key: Blob;
}
export interface PublicConfig {
  email_verification_required: boolean;
}
export interface VaultData {
  items: Record<string, Blob>;
  manifest: Blob | null;
  revision: number;
}

export type VaultOperation =
  | { op: "put"; id: string; blob: Blob }
  | { op: "delete"; id: string };

/** A published Send identity (opaque to the server; routing/crypto only). */
export interface SendPublic {
  enc_pub: number[];
  sig_pub: number[];
  key_version: number;
}
export interface InboxItem {
  message_id: string;
  blob: unknown;
  created_at: number;
  expires_at: number | null;
}

export class ApiError extends Error {
  status: number;
  /** Bounded remote text for diagnostics only. Never render this in the UI. */
  serverDetail: string;
  constructor(status: number, message: string, serverDetail = "") {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.serverDetail = serverDetail;
  }
}

/**
 * Fixed local copy for failures. The sync server is outside the browser trust
 * boundary, so its response body must never become user-facing text.
 */
export function statusMessage(status: number): string {
  if (status === 401) return "The server rejected the session or credentials.";
  if (status === 403) return "Mailbox verification is required or has expired.";
  if (status === 404) return "Not found on the server.";
  if (status === 409) return "The server reported a conflict with another change.";
  if (status === 413) return "The request is too large for the server.";
  if (status === 429) return "The server is rate-limiting requests. Try again shortly.";
  if (status >= 500) return "The server hit an internal error.";
  return `The server rejected the request (HTTP ${status}).`;
}

/** Bound hostile error bodies before retaining a short diagnostic excerpt. */
async function readErrorBody(response: Response): Promise<string> {
  try {
    const reader = response.body?.getReader();
    if (!reader) return ((await response.text()) || "").slice(0, MAX_ERROR_BODY_CHARS);
    const decoder = new TextDecoder();
    let output = "";
    while (output.length < MAX_ERROR_BODY_CHARS) {
      const { done, value } = await reader.read();
      if (done) break;
      output += decoder.decode(value, { stream: true });
    }
    await reader.cancel().catch(() => undefined);
    return output.slice(0, MAX_ERROR_BODY_CHARS);
  } catch {
    return "";
  }
}

/** Stream and bound a successful JSON response before parsing it. */
export async function readJsonBody<T>(
  response: Response,
  maxBytes: number = MAX_SUCCESS_BODY_BYTES
): Promise<T> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength &&
    /^[0-9]+$/.test(declaredLength) &&
    BigInt(declaredLength) > BigInt(maxBytes)
  ) {
    throw new ApiError(response.status, "Server response exceeded the safe size limit.");
  }
  const reader = response.body?.getReader();
  if (!reader) {
    throw new ApiError(response.status, "Server returned an unreadable JSON response.");
  }
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytesRead += value.byteLength;
    if (bytesRead > maxBytes) {
      await reader.cancel().catch(() => undefined);
      throw new ApiError(response.status, "Server response exceeded the safe size limit.");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(response.status, "Server returned invalid JSON.");
  }
}

/**
 * Fired on `window` when a request that carried a session token is rejected
 * with 401 — i.e. the server no longer honors the session (expired/revoked).
 * The app listens while the vault is open and locks immediately, instead of
 * leaving the user on a screen whose every action fails.
 */
export const SESSION_EXPIRED_EVENT = "bastion:session-expired";

export function isJsonMediaType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

async function req<T>(
  method: string,
  path: string,
  token?: string,
  body?: unknown,
  responseKind: "json" | "empty" = "json"
): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
      // A bearer token must never chase a redirect (a misconfigured or
      // compromised ingress could bounce it toward another origin), the API
      // uses no cookie/ambient credentials, and neither requests nor responses
      // belong in any HTTP cache.
      redirect: "error",
      credentials: "omit",
      cache: "no-store",
      referrerPolicy: "no-referrer",
    });
    if (!res.ok) {
      if (res.status === 401 && token) {
        window.dispatchEvent(new CustomEvent(SESSION_EXPIRED_EVENT));
      }
      const detail = await readErrorBody(res);
      throw new ApiError(
        res.status,
        statusMessage(res.status),
        detail.slice(0, MAX_SERVER_DETAIL_CHARS)
      );
    }
    if (responseKind === "empty") return undefined as T;
    if (!isJsonMediaType(res.headers.get("content-type"))) {
      throw new ApiError(res.status, "Server returned a non-JSON response.");
    }
    return await readJsonBody<T>(res);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new ApiError(0, "Server request timed out. The result is unknown; refresh before retrying.");
    }
    if (error instanceof ApiError) throw error;
    throw new ApiError(0, "Cannot reach the server. Is it running? (cargo run -p server)");
  } finally {
    window.clearTimeout(timer);
  }
}

export const api = {
  config: () => req<PublicConfig>("GET", "/config"),
  requestRegistrationChallenge: (email: string) =>
    req<void>("POST", "/registration-challenges", undefined, { email }, "empty"),
  verifyRegistrationChallenge: (token: string) =>
    req<{ email: string }>("POST", "/registration-challenges/verify", undefined, { token }),
  createAccount: (email: string, registration: Registration, mailboxProof?: string) =>
    req<void>(
      "POST",
      "/accounts",
      undefined,
      {
        email,
        registration,
        ...(mailboxProof ? { mailbox_proof: mailboxProof } : {}),
      },
      "empty"
    ),
  prelogin: (email: string) => req<Prelogin>("GET", `/accounts/${encodeURIComponent(email)}/prelogin`),
  login: (email: string, auth_secret: string) =>
    req<{ token: string }>("POST", "/sessions", undefined, { email, auth_secret }).then((r) => r.token),
  logout: (token: string) => req<void>("DELETE", "/sessions", token, undefined, "empty"),
  deleteAccount: (token: string, auth_secret: string) =>
    req<void>("DELETE", "/accounts", token, { auth_secret }, "empty"),
  getVault: (token: string) => req<VaultData>("GET", "/vault", token),
  mutateVault: (
    token: string,
    expectedRevision: number,
    operations: VaultOperation[],
    manifest: Blob
  ) =>
    req<{ revision: number }>("PUT", "/vault/transaction", token, {
      expected_revision: expectedRevision,
      operations,
      manifest,
    }),

  // ── Bastion Send ──
  publishIdentity: (token: string, pub: SendPublic) =>
    req<{ bastion_id: string }>("PUT", "/send/identity", token, pub),
  whoami: (token: string) => req<{ bastion_id: string; public: SendPublic }>("GET", "/send/whoami", token),
  directory: (token: string, bastionId: string) =>
    req<SendPublic>("GET", `/send/directory/${encodeURIComponent(bastionId)}`, token),
  sendBlob: (token: string, body: { recipient_id: string; message_id: string; blob: unknown; expires_at?: number | null }) =>
    req<void>("POST", "/send", token, body, "empty"),
  inbox: (token: string) => req<InboxItem[]>("GET", "/send/inbox", token),
  inboxDelete: (token: string, messageId: string) =>
    req<void>("DELETE", `/send/inbox/${encodeURIComponent(messageId)}`, token, undefined, "empty"),
};
