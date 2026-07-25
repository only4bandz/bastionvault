import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_CONTENT_ITEM_ID_CHARS,
  MAX_STAGED_PASSWORD_CHARS,
  MAX_STAGED_USERNAME_CHARS,
  validContentMessage,
} from "../lib/content-message-policy.js";

test("accepts the bounded content-script message contract", () => {
  assert.equal(validContentMessage({ type: "SUGGEST" }), true);
  assert.equal(validContentMessage({ type: "CREDS", id: "a".repeat(MAX_CONTENT_ITEM_ID_CHARS) }), true);
  assert.equal(validContentMessage({ type: "STAGE_USER", username: "alice" }), true);
  assert.equal(
    validContentMessage({
      type: "STAGE_SAVE",
      username: "alice",
      password: "x".repeat(MAX_STAGED_PASSWORD_CHARS),
    }),
    true
  );
  assert.equal(validContentMessage({ type: "SAVE_LOGIN", username: "" }), true);
});

test("rejects oversized credential material before session storage", () => {
  assert.equal(
    validContentMessage({ type: "STAGE_USER", username: "x".repeat(MAX_STAGED_USERNAME_CHARS + 1) }),
    false
  );
  assert.equal(
    validContentMessage({
      type: "STAGE_SAVE",
      username: "",
      password: "x".repeat(MAX_STAGED_PASSWORD_CHARS + 1),
    }),
    false
  );
  assert.equal(
    validContentMessage({ type: "CREDS", id: "x".repeat(MAX_CONTENT_ITEM_ID_CHARS + 1) }),
    false
  );
});

test("rejects malformed, missing, and privileged messages", () => {
  for (const message of [
    null,
    [],
    { type: "STAGE_SAVE", username: "alice", password: 123 },
    { type: "CREDS", id: "" },
    { type: "UNLOCK", password: "secret" },
    { type: "__proto__" },
    { type: "SUGGEST", ignored: "x" },
  ]) {
    assert.equal(validContentMessage(message), false);
  }
});
