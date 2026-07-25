import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiError,
  isJsonMediaType,
  makeApi,
  MAX_ERROR_BODY_BYTES,
  readErrorBody,
  requireInboxResponse,
  requirePreloginResponse,
  requirePublishedIdentityResponse,
  requireRevisionResponse,
  requireSendPublicResponse,
  requireSessionTokenResponse,
  requireVaultResponse,
  requireWhoamiResponse,
} from "../lib/api.js";

test("accepts only the endpoint's exact success status", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response('{"items":{},"manifest":null,"revision":0}', {
      status: 206,
      headers: { "content-type": "application/json" },
    });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com").getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 206 &&
        error.message ===
          "Server returned an unexpected success status (expected HTTP 200)."
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("validates complete Send inbox envelopes before crypto processing", () => {
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
    { message_id: messageId, blob, created_at: 100, expires_at: null },
  ];
  assert.deepEqual(requireInboxResponse(inbox), inbox);
  for (const value of [
    [{ ...inbox[0], created_at: -1 }],
    [{ ...inbox[0], expires_at: 100 }],
    [{ ...inbox[0], blob: { ...blob, type: "legacy" } }],
    [{ ...inbox[0], blob: { ...blob, wrapped_cek: body } }],
    [{ ...inbox[0], extra: true }],
  ]) {
    assert.throws(
      () => requireInboxResponse(value),
      /invalid Send inbox response/
    );
  }
});

test("validates every Send identity response envelope", () => {
  const bastionId = "A".repeat(26);
  const publicIdentity = {
    enc_pub: Array(32).fill(1),
    sig_pub: Array(32).fill(2),
    key_version: 1,
  };
  assert.deepEqual(requireSendPublicResponse(publicIdentity), publicIdentity);
  assert.deepEqual(requirePublishedIdentityResponse({ bastion_id: bastionId }), {
    bastion_id: bastionId,
  });
  assert.deepEqual(
    requireWhoamiResponse({ bastion_id: bastionId, public: publicIdentity }),
    { bastion_id: bastionId, public: publicIdentity }
  );
  for (const value of [
    { ...publicIdentity, enc_pub: Array(33).fill(1) },
    { ...publicIdentity, sig_pub: [...Array(31).fill(2), -1] },
    { ...publicIdentity, key_version: 0 },
    { ...publicIdentity, extra: true },
  ]) {
    assert.throws(
      () => requireSendPublicResponse(value),
      /invalid Send identity/
    );
  }
  for (const bastion_id of ["a".repeat(26), `${"A".repeat(25)}B`, "A".repeat(25)]) {
    assert.throws(
      () => requirePublishedIdentityResponse({ bastion_id }),
      /invalid Send identity response/
    );
  }
});

test("validates the complete encrypted vault envelope", () => {
  const blob = {
    v: 1,
    nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
    ct: "AAECAwQFBgcICQoLDA0ODw==",
  };
  const vault = { items: { "item-1": blob }, manifest: blob, revision: 4 };
  assert.deepEqual(requireVaultResponse(vault), vault);
  assert.deepEqual(requireVaultResponse({ items: {}, manifest: null, revision: 0 }), {
    items: {},
    manifest: null,
    revision: 0,
  });
  for (const value of [
    { ...vault, revision: Number.MAX_SAFE_INTEGER + 1 },
    { ...vault, items: { "bad/item": blob } },
    { ...vault, items: { "item-1": { ...blob, ct: "not-base64" } } },
    { ...vault, manifest: [] },
    { ...vault, extra: true },
  ]) {
    assert.throws(() => requireVaultResponse(value), /invalid vault response/);
  }
});

test("accepts only the canonical prelogin envelope", () => {
  const prelogin = {
    salt: "AAECAwQFBgcICQoLDA0ODw==",
    kdf: { mem_kib: 65_536, iterations: 3, parallelism: 1 },
    wrapped_vault_key: {
      v: 1,
      nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
      ct: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
    },
  };
  assert.deepEqual(requirePreloginResponse(prelogin), prelogin);
  for (const value of [
    { ...prelogin, salt: "not-base64" },
    { ...prelogin, kdf: { ...prelogin.kdf, mem_kib: 0 } },
    {
      ...prelogin,
      wrapped_vault_key: { ...prelogin.wrapped_vault_key, nonce: "short" },
    },
    { ...prelogin, extra: true },
  ]) {
    assert.throws(
      () => requirePreloginResponse(value),
      /invalid prelogin response/
    );
  }
});

test("sends account deletion proof to the canonical v1 endpoint", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 204 });
  };
  try {
    await makeApi("https://vault.example.com").deleteAccount("token", "derived-secret");
    assert.equal(request.url, "https://vault.example.com/v1/accounts");
    assert.equal(request.options.method, "DELETE");
    assert.equal(request.options.headers.Authorization, "Bearer token");
    assert.equal(request.options.redirect, "error");
    assert.equal(request.options.credentials, "omit");
    assert.equal(request.options.cache, "no-store");
    assert.equal(request.options.referrerPolicy, "no-referrer");
    assert.deepEqual(JSON.parse(request.options.body), {
      auth_secret: "derived-secret",
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("reads the canonical authenticated vault revision probe", async () => {
  const originalFetch = globalThis.fetch;
  let request;
  globalThis.fetch = async (url, options) => {
    request = { url, options };
    return new Response(JSON.stringify({ revision: 9 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    const head = await makeApi("https://vault.example.com").getVaultRevision("token");
    assert.deepEqual(head, { revision: 9 });
    assert.equal(request.url, "https://vault.example.com/v1/vault/revision");
    assert.equal(request.options.headers.Authorization, "Bearer token");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("accepts only exact non-negative safe revision envelopes", () => {
  assert.deepEqual(requireRevisionResponse({ revision: 9 }), { revision: 9 });
  for (const value of [
    { revision: -1 },
    { revision: 1.5 },
    { revision: Number.MAX_SAFE_INTEGER + 1 },
    { revision: 9, extra: true },
    { revision: "9" },
    null,
  ]) {
    assert.throws(() => requireRevisionResponse(value), /invalid revision response/);
  }
});

test("accepts only the exact JSON media type with optional parameters", () => {
  assert.equal(isJsonMediaType("application/json"), true);
  assert.equal(isJsonMediaType("Application/JSON; charset=utf-8"), true);
  assert.equal(isJsonMediaType("text/application/json"), false);
  assert.equal(isJsonMediaType("application/json-malicious"), false);
  assert.equal(isJsonMediaType(null), false);
});

test("fails closed when a JSON endpoint returns another media type", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response('{"revision":9}', {
      status: 200,
      headers: { "content-type": "text/plain" },
    });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com").getVaultRevision("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 200 &&
        error.message === "Server returned a non-JSON response."
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("accepts only the canonical session-token envelope", () => {
  const token = "ab".repeat(32);
  assert.equal(requireSessionTokenResponse({ token }), token);
  for (const value of [
    { token: token.toUpperCase() },
    { token: `${token}00` },
    { token, extra: true },
    { token: 7 },
    null,
  ]) {
    assert.throws(
      () => requireSessionTokenResponse(value),
      /invalid session response/
    );
  }
});

test("rejects a malformed successful login before exposing a bearer token", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response('{"token":"attacker-controlled"}', {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com").login("a@b.c", "derived-secret"),
      (error) =>
        error instanceof ApiError &&
        error.status === 200 &&
        error.message === "Server returned an invalid session response."
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

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
  globalThis.fetch = async () => new Response("{bad json", {
    status: 200,
    headers: { "content-type": "application/json" },
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
    return new Response(JSON.stringify({ revision: 8 }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
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
    assert.equal(request.url, "https://vault.example.com/v1/vault/transaction");
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

test("rejects oversized successful JSON before parsing it", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(JSON.stringify({ vault: "x".repeat(128) }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com", { maxResponseBytes: 32 }).getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.status === 200 &&
        error.message === "Server response exceeded the safe size limit."
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects an oversized declared response before reading the body", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response("{}", {
      status: 200,
      headers: {
        "content-type": "application/json",
        "content-length": "1000",
      },
    });
  try {
    await assert.rejects(
      makeApi("https://vault.example.com", { maxResponseBytes: 32 }).getVault("token"),
      (error) =>
        error instanceof ApiError &&
        error.message === "Server response exceeded the safe size limit."
    );
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

test("caps hostile multibyte error bodies by encoded bytes", async () => {
  const detail = await readErrorBody(new Response("é".repeat(10_000), { status: 503 }));
  assert.ok(new TextEncoder().encode(detail).byteLength <= MAX_ERROR_BODY_BYTES);
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
