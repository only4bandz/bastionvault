import assert from "node:assert/strict";
import test from "node:test";

import { isVaultItemPayload } from "../lib/vault-item-state.js";

const valid = {
  id: "item-1",
  type: "login",
  title: "Example",
  username: "alice",
  password: "secret",
  updatedAt: 1,
};

test("accepts canonical active and deleted vault items", () => {
  assert.equal(isVaultItemPayload(valid, "item-1"), true);
  assert.equal(isVaultItemPayload({ ...valid, deletedAt: 2 }, "item-1"), true);
});

test("rejects substituted, extensible, oversized, and unsafe vault items", () => {
  for (const item of [
    { ...valid, id: "item-2" },
    { ...valid, injected: true },
    { ...valid, title: "" },
    { ...valid, updatedAt: Number.MAX_SAFE_INTEGER },
    { ...valid, passwordChangedAt: -1 },
    { ...valid, deletedAt: 1.5 },
    { ...valid, url: "x".repeat(8 * 1024 + 1) },
    { ...valid, folder: "é".repeat(41) },
    { ...valid, notes: "x".repeat(256 * 1024 + 1) },
  ]) {
    assert.equal(isVaultItemPayload(item, "item-1"), false);
  }
});
