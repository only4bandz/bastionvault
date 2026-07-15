import assert from "node:assert/strict";
import test from "node:test";

import {
  makeStagedUsername,
  stagedUsernameFor,
  STAGED_USERNAME_TTL_MS,
} from "../lib/staged-username.js";

test("returns a staged username only to the same host", () => {
  const staged = makeStagedUsername(" alice@example.com ", "accounts.example.com", 1000);
  assert.equal(stagedUsernameFor(staged, "accounts.example.com", 1001), "alice@example.com");
  assert.equal(stagedUsernameFor(staged, "phishing.example.net", 1001), "");
});

test("expires staged usernames", () => {
  const staged = makeStagedUsername("alice", "example.com", 1000);
  assert.equal(stagedUsernameFor(staged, "example.com", 1000 + STAGED_USERNAME_TTL_MS), "alice");
  assert.equal(stagedUsernameFor(staged, "example.com", 1001 + STAGED_USERNAME_TTL_MS), "");
});

test("rejects legacy and malformed records", () => {
  assert.equal(stagedUsernameFor("legacy-global-user", "example.com", 1000), "");
  assert.equal(stagedUsernameFor({ username: "alice" }, "example.com", 1000), "");
  assert.equal(makeStagedUsername("", "example.com", 1000), null);
});
