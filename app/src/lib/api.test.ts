import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  ApiError,
  isJsonMediaType,
  MAX_ERROR_BODY_BYTES,
  MAX_SERVER_DETAIL_CHARS,
  readErrorBody,
  readJsonBody,
  requireInboxResponse,
  requirePreloginResponse,
  requirePublicConfigResponse,
  requirePublishedIdentityResponse,
  requireRevisionResponse,
  requireSendPublicResponse,
  requireSessionTokenResponse,
  requireVaultResponse,
  requireVerificationResponse,
  requireWhoamiResponse,
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
    const fetchMock = vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
      if (String(input).endsWith("/verify")) {
        return new Response('{"email":"alice@example.com"}', {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      }
      return new Response(null, { status: 204 });
    });
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

  it("caps hostile multibyte diagnostics by encoded bytes", async () => {
    const detail = await readErrorBody(new Response("é".repeat(10_000), { status: 503 }));
    expect(new TextEncoder().encode(detail).byteLength).toBeLessThanOrEqual(
      MAX_ERROR_BODY_BYTES
    );
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

describe("hostile successful response handling", () => {
  it("validates complete Send inbox envelopes before crypto processing", () => {
    const messageId = "AAECAwQFBgcICQoLDA0ODw==";
    const recipientId = "A".repeat(26);
    const nonce = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX";
    const key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    const wrapped = {
      v: 1,
      nonce,
      ct: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
    };
    const body = { v: 1, nonce, ct: "AAECAwQFBgcICQoLDA0ODw==" };
    const blob = {
      v: 1,
      type: "send",
      message_id: messageId,
      recipient_id: recipientId,
      recipient_enc_pub: key,
      recipient_key_version: 1,
      eph_pub: key,
      wrapped_cek: wrapped,
      cek_commit: key,
      body,
    };
    const inbox = [
      { message_id: messageId, blob, created_at: 100, expires_at: 200 },
    ];
    expect(requireInboxResponse(inbox)).toEqual(inbox);
    for (const value of [
      [{ ...inbox[0], message_id: "not-base64" }],
      [{ ...inbox[0], expires_at: 100 }],
      [{ ...inbox[0], blob: { ...blob, message_id: "AAAAAAAAAAAAAAAAAAAAAA==" } }],
      [{ ...inbox[0], blob: { ...blob, wrapped_cek: body } }],
      [{ ...inbox[0], extra: true }],
    ]) {
      expect(() => requireInboxResponse(value)).toThrow(
        "Server returned an invalid Send inbox response."
      );
    }
  });

  it("validates every Send identity response envelope", () => {
    const bastionId = "A".repeat(26);
    const publicIdentity = {
      enc_pub: Array(32).fill(1),
      sig_pub: Array(32).fill(2),
      key_version: 1,
    };
    expect(requireSendPublicResponse(publicIdentity)).toEqual(publicIdentity);
    expect(requirePublishedIdentityResponse({ bastion_id: bastionId })).toEqual({
      bastion_id: bastionId,
    });
    expect(
      requireWhoamiResponse({ bastion_id: bastionId, public: publicIdentity })
    ).toEqual({ bastion_id: bastionId, public: publicIdentity });

    for (const value of [
      { ...publicIdentity, enc_pub: Array(31).fill(1) },
      { ...publicIdentity, sig_pub: [...Array(31).fill(2), 256] },
      { ...publicIdentity, key_version: 2 },
      { ...publicIdentity, extra: true },
    ]) {
      expect(() => requireSendPublicResponse(value)).toThrow(
        "Server returned an invalid Send identity."
      );
    }
    for (const bastion_id of ["a".repeat(26), `${"A".repeat(25)}B`, "A".repeat(27)]) {
      expect(() => requirePublishedIdentityResponse({ bastion_id })).toThrow(
        "Server returned an invalid Send identity response."
      );
    }
  });

  it("validates the complete encrypted vault envelope", () => {
    const blob = {
      v: 1,
      nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      ct: "AAECAwQFBgcICQoLDA0ODw==",
    };
    const vault = { items: { "item-1": blob }, manifest: blob, revision: 4 };
    expect(requireVaultResponse(vault)).toEqual(vault);
    expect(requireVaultResponse({ items: {}, manifest: null, revision: 0 })).toEqual({
      items: {},
      manifest: null,
      revision: 0,
    });

    for (const value of [
      { ...vault, revision: -1 },
      { ...vault, items: { "bad/item": blob } },
      { ...vault, items: { "item-1": { ...blob, extra: true } } },
      { ...vault, manifest: { ...blob, nonce: "short" } },
      { ...vault, unexpected: true },
    ]) {
      expect(() => requireVaultResponse(value)).toThrow(
        "Server returned an invalid vault response."
      );
    }
  });

  it("accepts only the canonical prelogin envelope", () => {
    const prelogin = {
      salt: "AAECAwQFBgcICQoLDA0ODw==",
      kdf: { mem_kib: 65_536, iterations: 3, parallelism: 1 },
      wrapped_vault_key: {
        v: 1,
        nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
        ct: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
      },
    };
    expect(requirePreloginResponse(prelogin)).toEqual(prelogin);
    for (const value of [
      { ...prelogin, salt: "not-base64" },
      { ...prelogin, kdf: { ...prelogin.kdf, iterations: 0 } },
      {
        ...prelogin,
        wrapped_vault_key: { ...prelogin.wrapped_vault_key, v: 2 },
      },
      { ...prelogin, extra: true },
    ]) {
      expect(() => requirePreloginResponse(value)).toThrow(
        "Server returned an invalid prelogin response."
      );
    }
  });

  it("validates configuration, verification, and revision envelopes", () => {
    expect(
      requirePublicConfigResponse({ email_verification_required: true })
    ).toEqual({ email_verification_required: true });
    expect(requireVerificationResponse({ email: "alice@example.com" })).toEqual({
      email: "alice@example.com",
    });
    expect(requireRevisionResponse({ revision: 7 })).toEqual({ revision: 7 });

    expect(() =>
      requirePublicConfigResponse({ email_verification_required: "yes" })
    ).toThrow(/configuration response/);
    expect(() =>
      requireVerificationResponse({ email: "", proof: "unexpected" })
    ).toThrow(/verification response/);
    expect(() => requireRevisionResponse({ revision: -1 })).toThrow(
      /revision response/
    );
    expect(() =>
      requireRevisionResponse({ revision: Number.MAX_SAFE_INTEGER + 1 })
    ).toThrow(/revision response/);
  });

  it("accepts only the canonical session-token envelope", () => {
    const token = "ab".repeat(32);
    expect(requireSessionTokenResponse({ token })).toBe(token);
    for (const value of [
      { token: token.toUpperCase() },
      { token: `${token}00` },
      { token, extra: true },
      { token: 7 },
      null,
    ]) {
      expect(() => requireSessionTokenResponse(value)).toThrow(
        "Server returned an invalid session response."
      );
    }
  });

  it("rejects a malformed successful login before exposing a bearer token", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () =>
      new Response('{"token":"attacker-controlled"}', {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    try {
      await expect(api.login("a@b.c", "derived-secret")).rejects.toMatchObject({
        status: 200,
        message: "Server returned an invalid session response.",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("accepts only the exact JSON media type with optional parameters", () => {
    expect(isJsonMediaType("application/json")).toBe(true);
    expect(isJsonMediaType("Application/JSON; charset=utf-8")).toBe(true);
    expect(isJsonMediaType("text/application/json")).toBe(false);
    expect(isJsonMediaType("application/json-malicious")).toBe(false);
    expect(isJsonMediaType(null)).toBe(false);
  });

  it("fails closed when a JSON endpoint returns another media type", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = vi.fn(async () =>
      new Response('{"salt":"attacker-controlled"}', {
        status: 200,
        headers: { "content-type": "text/plain" },
      })
    );
    try {
      await expect(api.prelogin("a@b.c")).rejects.toMatchObject({
        status: 200,
        message: "Server returned a non-JSON response.",
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  it("rejects a streamed response above the configured byte ceiling", async () => {
    const response = new Response(JSON.stringify({ vault: "x".repeat(128) }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });

    await expect(readJsonBody(response, 32)).rejects.toMatchObject({
      status: 200,
      message: "Server response exceeded the safe size limit.",
    });
  });

  it("rejects an oversized declared response before reading it", async () => {
    const response = new Response("{}", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": "1000",
      },
    });

    await expect(readJsonBody(response, 32)).rejects.toMatchObject({
      message: "Server response exceeded the safe size limit.",
    });
  });

  it("parses a bounded successful JSON response", async () => {
    const response = new Response('{"revision":9}', {
      status: 200,
      headers: { "content-type": "application/json" },
    });

    await expect(readJsonBody<{ revision: number }>(response, 32)).resolves.toEqual({
      revision: 9,
    });
  });
});
