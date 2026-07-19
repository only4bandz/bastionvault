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
    expect(statusMessage(404)).toMatch(/not found/i);
    expect(statusMessage(409)).toMatch(/conflict/i);
    expect(statusMessage(413)).toMatch(/too large/i);
    expect(statusMessage(429)).toMatch(/rate-limiting/i);
    expect(statusMessage(503)).toMatch(/internal error/i);
    expect(statusMessage(418)).toBe("The server rejected the request (HTTP 418).");
  });
});
