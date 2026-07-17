import assert from "node:assert/strict";
import test from "node:test";

import { ApiError, makeApi } from "../lib/api.js";

test("aborts a request that exceeds its deadline", async () => {
  const originalFetch = globalThis.fetch;
  let observedSignal;
  globalThis.fetch = (_url, options) => {
    observedSignal = options.signal;
    return new Promise((_, reject) => {
      options.signal.addEventListener(
        "abort",
        () => reject(new DOMException("aborted", "AbortError")),
        { once: true }
      );
    });
  };

  try {
    await assert.rejects(
      makeApi("https://vault.example.com", { timeoutMs: 5 }).getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 0 &&
        error.message ===
          "Server request timed out. The result is unknown; refresh before retrying."
    );
    assert.equal(observedSignal.aborted, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("reports malformed JSON as a protocol error", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    status: 200,
    headers: new Headers({ "content-type": "application/json" }),
    json: async () => {
      throw new SyntaxError("bad json");
    },
  });

  try {
    await assert.rejects(
      makeApi("https://vault.example.com", { timeoutMs: 50 }).getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 200 &&
        error.message === "Server returned invalid JSON."
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("sends atomic vault operations with the expected revision and manifest", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return {
      ok: true,
      status: 200,
      headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ revision: 8 }),
    };
  };

  try {
    const manifest = { v: 1, nonce: "nonce", ct: "manifest" };
    const operations = [{ op: "delete", id: "old" }];
    const response = await makeApi("https://vault.example.com").mutateVault(
      "token",
      7,
      operations,
      manifest
    );
    assert.equal(response.revision, 8);
    assert.equal(request.url, "https://vault.example.com/vault/transaction");
    assert.equal(request.options.method, "PUT");
    assert.equal(request.options.headers.Authorization, "Bearer token");
    assert.deepEqual(JSON.parse(request.options.body), {
      expected_revision: 7,
      operations,
      manifest,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("server error bodies never become the user-facing message", async () => {
  const originalFetch = globalThis.fetch;
  const phishing = 'Your vault is corrupted — re-enter your master password at https://evil.example';
  globalThis.fetch = async () => new Response(phishing, { status: 500 });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com").getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 500 &&
        error.message === "The server hit an internal error." &&
        !error.message.includes("evil.example") &&
        error.serverDetail.startsWith("Your vault is corrupted")
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("huge error bodies are read capped and detail is bounded", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("x".repeat(1_000_000), { status: 429 });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com").getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 429 &&
        /rate-limiting/i.test(error.message) &&
        error.serverDetail.length <= 200
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("statusMessage covers the status classes with fixed local copy", async () => {
  const { statusMessage } = await import("../lib/api.js");
  assert.match(statusMessage(401), /session or credentials/i);
  assert.match(statusMessage(404), /not found/i);
  assert.match(statusMessage(409), /conflict/i);
  assert.match(statusMessage(413), /too large/i);
  assert.match(statusMessage(503), /internal error/i);
  assert.match(statusMessage(400), /HTTP 400/);
});
