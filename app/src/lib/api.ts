// Client for the zero-knowledge sync server. In dev, requests go through the
// Vite proxy (/api -> http://127.0.0.1:7777). The server only ever sees opaque
// encrypted blobs + a hash of the auth secret — never plaintext.
const BASE = "/api";

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
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function req<T>(method: string, path: string, token?: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let res: Response;
  try {
    res = await fetch(BASE + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "Cannot reach the server. Is it running? (cargo run -p server)");
  }
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new ApiError(res.status, text || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  return (ct.includes("application/json") ? await res.json() : (undefined as T)) as T;
}

export const api = {
  createAccount: (email: string, registration: Registration) =>
    req<void>("POST", "/accounts", undefined, { email, registration }),
  prelogin: (email: string) => req<Prelogin>("GET", `/accounts/${encodeURIComponent(email)}/prelogin`),
  login: (email: string, auth_secret: string) =>
    req<{ token: string }>("POST", "/sessions", undefined, { email, auth_secret }).then((r) => r.token),
  logout: (token: string) => req<void>("DELETE", "/sessions", token),
  getVault: (token: string) => req<VaultData>("GET", "/vault", token),
  putItem: (token: string, id: string, blob: Blob) =>
    req<void>("PUT", `/vault/items/${encodeURIComponent(id)}`, token, { blob }),
  deleteItem: (token: string, id: string) =>
    req<void>("DELETE", `/vault/items/${encodeURIComponent(id)}`, token),
};
