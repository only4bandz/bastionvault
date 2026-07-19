// Client for the zero-knowledge sync server. In dev, requests go through the
// Vite proxy (/api -> http://127.0.0.1:7777). The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.
const BASE = "/api";
const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_ERROR_BODY_CHARS = 4096;
export const MAX_SERVER_DETAIL_CHARS = 200;

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

/**
 * Fired on `window` when a request that carried a session token is rejected
 * with 401 — i.e. the server no longer honors the session (expired/revoked).
 * The app listens while the vault is open and locks immediately, instead of
 * leaving the user on a screen whose every action fails.
 */
export const SESSION_EXPIRED_EVENT = "bastion:session-expired";

async function req<T>(method: string, path: string, token?: string, body?: unknown): Promise<T> {
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
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("application/json")) return undefined as T;
    try {
      return (await res.json()) as T;
    } catch {
      throw new ApiError(res.status, "Server returned invalid JSON.");
    }
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
  createAccount: (email: string, registration: Registration) =>
    req<void>("POST", "/accounts", undefined, { email, registration }),
  prelogin: (email: string) => req<Prelogin>("GET", `/accounts/${encodeURIComponent(email)}/prelogin`),
  login: (email: string, auth_secret: string) =>
    req<{ token: string }>("POST", "/sessions", undefined, { email, auth_secret }).then((r) => r.token),
  logout: (token: string) => req<void>("DELETE", "/sessions", token),
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
    req<void>("POST", "/send", token, body),
  inbox: (token: string) => req<InboxItem[]>("GET", "/send/inbox", token),
  inboxDelete: (token: string, messageId: string) =>
    req<void>("DELETE", `/send/inbox/${encodeURIComponent(messageId)}`, token),
};
