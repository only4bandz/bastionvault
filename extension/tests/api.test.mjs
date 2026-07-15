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
