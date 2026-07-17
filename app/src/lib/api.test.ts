import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, ApiError, SESSION_EXPIRED_EVENT } from "./api";

function respond(status: number, body = ""): Response {
  return new Response(body, {
    status,
    headers: { "content-type": "text/plain" },
  });
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
