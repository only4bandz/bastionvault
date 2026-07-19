import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  ApiError,
  MAX_SERVER_DETAIL_CHARS,
  SESSION_EXPIRED_EVENT,
  statusMessage,
} from "./api";

function respond(status: number, body = ""): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain" },
  });
}

async function captureApiError(promise: Promise<unknown>): Promise<ApiError> {
  try {
    await promise;
  } catch (error) {
    if (error instanceof ApiError) return error;
    throw error;
  }
  throw new Error("Expected API request to fail.");
}

describe("versioned account lifecycle client", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("sends deletion proof only to the canonical v1 endpoint", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(null, { status: 204 })
    );
    globalThis.fetch = fetchMock;

    await api.deleteAccount("token", "derived-secret");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/accounts");
    expect(options).toMatchObject({
      method: "DELETE",
      body: JSON.stringify({ auth_secret: "derived-secret" }),
    });
    expect(options?.headers).toMatchObject({ Authorization: "Bearer token" });
  });

  it("sends mailbox challenges and proof only to canonical endpoints", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(null, { status: 204 })
    );
    globalThis.fetch = fetchMock;

    await api.requestRegistrationChallenge("alice@example.com");
    await api.verifyRegistrationChallenge("proof-token");
    await api.createAccount(
      "alice@example.com",
      {
        version: 1,
        salt: "salt",
        kdf: { mem_kib: 65536, iterations: 3, parallelism: 1 },
        wrapped_vault_key: { v: 1, nonce: "nonce", ct: "ciphertext" },
        auth_secret: "secret",
      },
      "proof-token"
    );

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      "/api/v1/registration-challenges",
      "/api/v1/registration-challenges/verify",
      "/api/v1/accounts",
    ]);
    expect(fetchMock.mock.calls[2][1]?.body).toContain('"mailbox_proof":"proof-token"');
  });
});

describe("session-expiry signaling", () => {
  const originalFetch = globalThis.fetch;
  let expired: number;
  const onExpired = () => {
    expired += 1;
  };

  beforeEach(() => {
    expired = 0;
    window.addEventListener(SESSION_EXPIRED_EVENT, onExpired);
  });

  afterEach(() => {
    window.removeEventListener(SESSION_EXPIRED_EVENT, onExpired);
    globalThis.fetch = originalFetch;
  });

  it("announces a 401 on a token-bearing request", async () => {
    globalThis.fetch = vi.fn(async () => respond(401));
    await expect(api.getVault("stale-token")).rejects.toMatchObject({ status: 401 });
    expect(expired).toBe(1);
  });

  it("stays silent for a 401 without a token (login failure is not expiry)", async () => {
    globalThis.fetch = vi.fn(async () => respond(401));
    await expect(api.login("a@b.c", "bad")).rejects.toBeInstanceOf(ApiError);
    expect(expired).toBe(0);
  });

  it("stays silent for authenticated non-401 failures", async () => {
    globalThis.fetch = vi.fn(async () => respond(429));
    await expect(api.getVault("token")).rejects.toMatchObject({ status: 429 });
    expect(expired).toBe(0);
  });
});

describe("hostile server error handling", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("never promotes remote error text into the user-facing message", async () => {
    const phishing = "Re-enter your master password at https://evil.example";
    globalThis.fetch = vi.fn(async () => respond(500, phishing));

    const error = await captureApiError(api.prelogin("a@b.c"));
    expect(error).toMatchObject({
      status: 500,
      message: "The server hit an internal error.",
      serverDetail: phishing,
    });
    expect(error.message).not.toContain("evil.example");
  });

  it("bounds retained diagnostics from a huge response body", async () => {
    globalThis.fetch = vi.fn(async () => respond(503, "x".repeat(100_000)));

    const error = await captureApiError(api.prelogin("a@b.c"));
    expect(error.message).toBe("The server hit an internal error.");
    expect(error.serverDetail).toHaveLength(MAX_SERVER_DETAIL_CHARS);
  });

  it("maps status classes to deterministic local copy", () => {
    expect(statusMessage(401)).toMatch(/session or credentials/i);
    expect(statusMessage(403)).toMatch(/mailbox verification/i);
    expect(statusMessage(404)).toMatch(/not found/i);
    expect(statusMessage(409)).toMatch(/conflict/i);
    expect(statusMessage(413)).toMatch(/too large/i);
    expect(statusMessage(429)).toMatch(/rate-limiting/i);
    expect(statusMessage(503)).toMatch(/internal error/i);
    expect(statusMessage(418)).toBe("The server rejected the request (HTTP 418).");
  });
});
