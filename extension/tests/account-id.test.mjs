import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_ACCOUNT_ID_CHARS,
  canonicalAccountId,
} from "../lib/account-id.js";

test("canonicalizes the complete ASCII account id", () => {
  assert.equal(canonicalAccountId("  Alice+Vault@Example.COM  "), "alice+vault@example.com");
  assert.equal(canonicalAccountId("alice@example.com"), "alice@example.com");
});

test("rejects ambiguous, non-ASCII, and oversized account ids", () => {
  for (const value of [
    null,
    "",
    "alice",
    "@example.com",
    "alice@",
    "alice@@example.com",
    "ali ce@example.com",
    "álîçé@example.com",
    "K@example.com",
    `a@${"x".repeat(MAX_ACCOUNT_ID_CHARS)}`,
  ]) {
    assert.throws(() => canonicalAccountId(value), /invalid account id/i);
  }
});
