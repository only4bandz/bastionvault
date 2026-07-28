// Client for the zero-knowledge sync server. In dev, requests go through the
// Vite proxy (/api -> http://127.0.0.1:7777). The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.
// Type-only on the other side (kdf-policy imports `Registration` as a type),
// so this shares the envelope constants without creating a runtime cycle.
import {
  MAX_ITERATIONS,
  MAX_MEM_KIB,
  MAX_PARALLELISM,
  MIN_ITERATIONS,
  MIN_MEM_KIB,
  MIN_PARALLELISM,
} from "./kdf-policy";

const BASE = "/api/v1";
const REQUEST_TIMEOUT_MS = 15_000;
export const MAX_ERROR_BODY_BYTES = 4096;
export const MAX_SERVER_DETAIL_CHARS = 200;
export const MAX_SUCCESS_BODY_BYTES = 80 * 1024 * 1024;
const MAX_VAULT_ITEMS = 10_000;
const MAX_ITEM_ID_BYTES = 256;
const MAX_VAULT_BLOB_BYTES = 512 * 1024;
const MAX_VAULT_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_INBOX_PAGE = 100;
const MAX_SEND_BLOB_BYTES = 256 * 1024;

/**
 * Per-endpoint success-body budgets.
 *
 * `readJsonBody` has always accepted a cap, but `req` never passed one — so
 * every response, including replies whose real size is a few dozen bytes,
 * inherited the 80 MiB ceiling and could be buffered into a JS string and
 * `JSON.parse`d before any schema validator ran. A hostile server (or an
 * MITM'd ingress on a deployment without HSTS) could crash the tab with a
 * reply to `/config` — before the user is even authenticated. The semantic
 * bounds enforced by the validators are all post-parse, so they are no help
 * here.
 *
 * Every budget below is derived from what the endpoint can legitimately
 * return, with generous headroom for JSON overhead.
 */
const SMALL_BODY_BYTES = 4 * 1024;
const VAULT_BODY_BYTES =
  MAX_VAULT_ITEMS * (MAX_VAULT_BLOB_BYTES + MAX_ITEM_ID_BYTES) + MAX_VAULT_MANIFEST_BYTES;
const INBOX_BODY_BYTES = MAX_INBOX_PAGE * (MAX_SEND_BLOB_BYTES + 4 * 1024);

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
export async function readErrorBody(response: Response): Promise<string> {
  try {
    const reader = response.body?.getReader();
    if (!reader) return "";
    const decoder = new TextDecoder();
    let output = "";
    let bytesRead = 0;
    while (bytesRead < MAX_ERROR_BODY_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = MAX_ERROR_BODY_BYTES - bytesRead;
      const accepted = value.subarray(0, remaining);
      bytesRead += accepted.byteLength;
      output += decoder.decode(accepted, { stream: true });
      if (accepted.byteLength < value.byteLength) break;
    }
    await reader.cancel().catch(() => undefined);
    output += decoder.decode();
    return output;
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

const sessionTokenAliases = new Map<string, string>();

function currentSessionToken(token: string): string {
  let current = token;
  const seen = new Set<string>();
  while (sessionTokenAliases.has(current) && !seen.has(current)) {
    seen.add(current);
    current = sessionTokenAliases.get(current)!;
  }
  return current;
}

function rememberSessionRotation(previous: string, successor: string): void {
  sessionTokenAliases.set(previous, successor);
}

function forgetSessionFamily(token: string): void {
  const current = currentSessionToken(token);
  for (const [candidate] of sessionTokenAliases) {
    if (currentSessionToken(candidate) === current) sessionTokenAliases.delete(candidate);
  }
  sessionTokenAliases.delete(current);
}

export function isJsonMediaType(value: string | null): boolean {
  return value?.split(";", 1)[0]?.trim().toLowerCase() === "application/json";
}

export function requireSessionTokenResponse(value: unknown): string {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.keys(value).length !== 1 ||
    !Object.prototype.hasOwnProperty.call(value, "token")
  ) {
    throw new ApiError(200, "Server returned an invalid session response.");
  }
  const token = (value as { token?: unknown }).token;
  if (typeof token !== "string" || !/^[0-9a-f]{64}$/.test(token)) {
    throw new ApiError(200, "Server returned an invalid session response.");
  }
  return token;
}

function exactRecord(value: unknown, keys: string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function canonicalBase64Length(value: unknown): number | null {
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

function exactBase64Bytes(value: unknown, decodedBytes: number): value is string {
  return canonicalBase64Length(value) === decodedBytes;
}

function requireEncryptedBlob(value: unknown, maxCiphertextBytes: number): value is Blob {
  if (!exactRecord(value, ["v", "nonce", "ct"]) || value.v !== 1) return false;
  const ciphertextBytes = canonicalBase64Length(value.ct);
  return (
    ciphertextBytes !== null &&
    ciphertextBytes >= 16 &&
    ciphertextBytes <= maxCiphertextBytes &&
    exactBase64Bytes(value.nonce, 24)
  );
}

function validItemId(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= MAX_ITEM_ID_BYTES &&
    /^[\x21-\x7e]+$/.test(value) &&
    !/[\\/ ?#]/.test(value)
  );
}

export function requireVaultResponse(value: unknown): VaultData {
  if (
    !exactRecord(value, ["items", "manifest", "revision"]) ||
    !Number.isSafeInteger(value.revision) ||
    (value.revision as number) < 0 ||
    typeof value.items !== "object" ||
    value.items === null ||
    Array.isArray(value.items)
  ) {
    throw new ApiError(200, "Server returned an invalid vault response.");
  }
  const items = Object.entries(value.items);
  if (
    items.length > MAX_VAULT_ITEMS ||
    items.some(
      ([id, blob]) =>
        !validItemId(id) || !requireEncryptedBlob(blob, MAX_VAULT_BLOB_BYTES)
    ) ||
    (value.manifest !== null &&
      !requireEncryptedBlob(value.manifest, MAX_VAULT_MANIFEST_BYTES))
  ) {
    throw new ApiError(200, "Server returned an invalid vault response.");
  }
  return value as unknown as VaultData;
}

function validBastionId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z2-7]{25}[AEIMQUY4]$/.test(value);
}

export function requireSendPublicResponse(value: unknown): SendPublic {
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
  return value as unknown as SendPublic;
}

export function requirePublishedIdentityResponse(value: unknown): { bastion_id: string } {
  if (
    !exactRecord(value, ["bastion_id"]) ||
    !validBastionId(value.bastion_id)
  ) {
    throw new ApiError(200, "Server returned an invalid Send identity response.");
  }
  return { bastion_id: value.bastion_id };
}

export function requireWhoamiResponse(
  value: unknown
): { bastion_id: string; public: SendPublic } {
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

/**
 * The `pw` block of an inbox blob is attacker-supplied: the sender chooses it
 * and the server can rewrite it. Hold it to the same Argon2id envelope every
 * other derivation in this app is held to, so out-of-envelope parameters are
 * refused before they ever reach WASM.
 */
function validSendPasswordParams(value: unknown): boolean {
  return (
    exactRecord(value, ["salt", "mem_kib", "iterations", "parallelism"]) &&
    exactBase64Bytes(value.salt, 16) &&
    inKdfEnvelope(value.mem_kib, MIN_MEM_KIB, MAX_MEM_KIB) &&
    inKdfEnvelope(value.iterations, MIN_ITERATIONS, MAX_ITERATIONS) &&
    inKdfEnvelope(value.parallelism, MIN_PARALLELISM, MAX_PARALLELISM)
  );
}

function inKdfEnvelope(value: unknown, min: number, max: number): boolean {
  return Number.isSafeInteger(value) && (value as number) >= min && (value as number) <= max;
}

function validSendBlob(value: unknown, messageId: string): boolean {
  const hasPassword =
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.prototype.hasOwnProperty.call(value, "pw");
  const keys = [
    "v",
    "type",
    "message_id",
    "recipient_id",
    "recipient_enc_pub",
    "recipient_key_version",
    "eph_pub",
    "wrapped_cek",
    "cek_commit",
    "body",
    ...(hasPassword ? ["pw"] : []),
  ];
  return (
    exactRecord(value, keys) &&
    value.v === 1 &&
    value.type === "send" &&
    value.message_id === messageId &&
    validBastionId(value.recipient_id) &&
    exactBase64Bytes(value.recipient_enc_pub, 32) &&
    Number.isSafeInteger(value.recipient_key_version) &&
    (value.recipient_key_version as number) > 0 &&
    exactBase64Bytes(value.eph_pub, 32) &&
    requireEncryptedBlob(value.wrapped_cek, 48) &&
    canonicalBase64Length(
      (value.wrapped_cek as { ct: unknown }).ct
    ) === 48 &&
    exactBase64Bytes(value.cek_commit, 32) &&
    requireEncryptedBlob(value.body, MAX_SEND_BLOB_BYTES) &&
    (!hasPassword || validSendPasswordParams(value.pw))
  );
}

export function requireInboxResponse(value: unknown): InboxItem[] {
  if (!Array.isArray(value) || value.length > MAX_INBOX_PAGE) {
    throw new ApiError(200, "Server returned an invalid Send inbox response.");
  }
  for (const item of value) {
    if (
      !exactRecord(item, ["message_id", "blob", "created_at", "expires_at"]) ||
      !exactBase64Bytes(item.message_id, 16) ||
      !Number.isSafeInteger(item.created_at) ||
      (item.created_at as number) < 0 ||
      (item.expires_at !== null &&
        (!Number.isSafeInteger(item.expires_at) ||
          (item.expires_at as number) <= (item.created_at as number))) ||
      !validSendBlob(item.blob, item.message_id as string)
    ) {
      throw new ApiError(200, "Server returned an invalid Send inbox response.");
    }
  }
  return value as InboxItem[];
}

export function requirePreloginResponse(value: unknown): Prelogin {
  if (
    !exactRecord(value, ["salt", "kdf", "wrapped_vault_key"]) ||
    !exactBase64Bytes(value.salt, 16) ||
    !exactRecord(value.kdf, ["mem_kib", "iterations", "parallelism"]) ||
    !Number.isSafeInteger(value.kdf.mem_kib) ||
    (value.kdf.mem_kib as number) <= 0 ||
    !Number.isSafeInteger(value.kdf.iterations) ||
    (value.kdf.iterations as number) <= 0 ||
    !Number.isSafeInteger(value.kdf.parallelism) ||
    (value.kdf.parallelism as number) <= 0 ||
    !exactRecord(value.wrapped_vault_key, ["v", "nonce", "ct"]) ||
    value.wrapped_vault_key.v !== 1 ||
    !exactBase64Bytes(value.wrapped_vault_key.nonce, 24) ||
    !exactBase64Bytes(value.wrapped_vault_key.ct, 48)
  ) {
    throw new ApiError(200, "Server returned an invalid prelogin response.");
  }
  return value as unknown as Prelogin;
}

export function requirePublicConfigResponse(value: unknown): PublicConfig {
  if (
    !exactRecord(value, ["email_verification_required"]) ||
    typeof value.email_verification_required !== "boolean"
  ) {
    throw new ApiError(200, "Server returned an invalid configuration response.");
  }
  return { email_verification_required: value.email_verification_required };
}

export function requireVerificationResponse(value: unknown): { email: string } {
  if (
    !exactRecord(value, ["email"]) ||
    typeof value.email !== "string" ||
    value.email.length === 0 ||
    value.email.length > 254
  ) {
    throw new ApiError(200, "Server returned an invalid verification response.");
  }
  return { email: value.email };
}

export function requireRevisionResponse(value: unknown): { revision: number } {
  if (
    !exactRecord(value, ["revision"]) ||
    typeof value.revision !== "number" ||
    !Number.isSafeInteger(value.revision) ||
    value.revision < 0
  ) {
    throw new ApiError(200, "Server returned an invalid revision response.");
  }
  return { revision: value.revision };
}

async function req<T>(
  method: string,
  path: string,
  token?: string,
  body?: unknown,
  responseKind: "json" | "empty" = "json",
  expectedStatus: number = responseKind === "json" ? 200 : 204,
  maxBytes: number = SMALL_BODY_BYTES
): Promise<T> {
  const authorizationToken = token ? currentSessionToken(token) : undefined;
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (authorizationToken) headers["Authorization"] = `Bearer ${authorizationToken}`;
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
    if (res.status !== expectedStatus) {
      await res.body?.cancel().catch(() => undefined);
      throw new ApiError(
        res.status,
        `Server returned an unexpected success status (expected HTTP ${expectedStatus}).`
      );
    }
    if (responseKind === "empty") return undefined as T;
    if (!isJsonMediaType(res.headers.get("content-type"))) {
      throw new ApiError(res.status, "Server returned a non-JSON response.");
    }
    return await readJsonBody<T>(res, maxBytes);
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
  config: () => req<unknown>("GET", "/config").then(requirePublicConfigResponse),
  requestRegistrationChallenge: (email: string) =>
    req<void>(
      "POST",
      "/registration-challenges",
      undefined,
      { email },
      "empty",
      202
    ),
  verifyRegistrationChallenge: (token: string) =>
    req<unknown>("POST", "/registration-challenges/verify", undefined, { token }).then(
      requireVerificationResponse
    ),
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
      "empty",
      201
    ),
  prelogin: (email: string) =>
    req<unknown>("GET", `/accounts/${encodeURIComponent(email)}/prelogin`).then(
      requirePreloginResponse
    ),
  login: (email: string, auth_secret: string) =>
    req<unknown>("POST", "/sessions", undefined, { email, auth_secret }).then(
      requireSessionTokenResponse
    ),
  rotateSession: async (token: string): Promise<string> => {
    const predecessor = currentSessionToken(token);
    // The replacement is minted by the server. A client cannot supply the
    // entropy of the server's own bearer credential, and the server has no way
    // to check a generator it does not control.
    const attempt = () =>
      req<unknown>("PUT", "/sessions", predecessor, {}, "json").then(
        requireSessionTokenResponse
      );
    let successor: string;
    try {
      successor = await attempt();
    } catch (error) {
      // Retry one ambiguous transport failure. The server answers a retry
      // safely: a successor that never authenticated a request is revoked and
      // replaced, while replaying a predecessor whose successor is already in
      // use revokes the family.
      if (!(error instanceof ApiError) || error.status !== 0) throw error;
      successor = await attempt();
    }
    rememberSessionRotation(predecessor, successor);
    rememberSessionRotation(token, successor);
    return successor;
  },
  logout: async (token: string) => {
    await req<void>("DELETE", "/sessions", token, undefined, "empty");
    forgetSessionFamily(token);
  },
  revokeAllSessions: async (token: string) => {
    await req<void>("DELETE", "/sessions/all", token, undefined, "empty");
    forgetSessionFamily(token);
  },
  deleteAccount: (token: string, auth_secret: string) =>
    req<void>("DELETE", "/accounts", token, { auth_secret }, "empty"),
  getVault: (token: string) =>
    req<unknown>("GET", "/vault", token, undefined, "json", 200, VAULT_BODY_BYTES).then(
      requireVaultResponse
    ),
  mutateVault: (
    token: string,
    expectedRevision: number,
    operations: VaultOperation[],
    manifest: Blob
  ) =>
    req<unknown>("PUT", "/vault/transaction", token, {
      expected_revision: expectedRevision,
      operations,
      manifest,
    }).then(requireRevisionResponse),

  // ── Bastion Send ──
  publishIdentity: (token: string, pub: SendPublic) =>
    req<unknown>("PUT", "/send/identity", token, pub).then(
      requirePublishedIdentityResponse
    ),
  whoami: (token: string) =>
    req<unknown>("GET", "/send/whoami", token).then(requireWhoamiResponse),
  directory: (token: string, bastionId: string) =>
    req<unknown>(
      "GET",
      `/send/directory/${encodeURIComponent(bastionId)}`,
      token
    ).then(requireSendPublicResponse),
  sendBlob: (token: string, body: { recipient_id: string; message_id: string; blob: unknown; expires_at?: number | null }) =>
    req<void>("POST", "/send", token, body, "empty"),
  inbox: (token: string) =>
    req<unknown>("GET", "/send/inbox", token, undefined, "json", 200, INBOX_BODY_BYTES).then(
      requireInboxResponse
    ),
  inboxDelete: (token: string, messageId: string) =>
    req<void>("DELETE", `/send/inbox/${encodeURIComponent(messageId)}`, token, undefined, "empty"),
};
