import assert from "node:assert/strict";
import test from "node:test";

import { loadVaultState, VaultIntegrityError } from "../lib/vault-load.js";

function account() {
  return {
    load_send_identity(blob) {
      if (JSON.parse(blob).corrupt) throw new Error("bad identity");
    },
    decrypt_item(blob) {
      const value = JSON.parse(blob);
      if (value.corrupt) throw new Error("bad ciphertext");
      return value.plaintext;
    },
  };
}

test("loads a complete valid vault", () => {
  const result = loadVaultState(account(), {
    item1: {
      plaintext: JSON.stringify({ id: "item1", type: "login", title: "Example", updatedAt: 1 }),
    },
    "bastion:send-contacts": { plaintext: "[]" },
  });
  assert.equal(result.items.size, 1);
  assert.deepEqual(result.contacts, []);
});

test("fails the entire load when one ciphertext is corrupt", () => {
  assert.throws(
    () =>
      loadVaultState(account(), {
        good: { plaintext: JSON.stringify({ id: "good", type: "note", title: "Good", updatedAt: 1 }) },
        bad: { corrupt: true },
      }),
    VaultIntegrityError
  );
});

test("rejects plaintext whose id does not match its authenticated storage id", () => {
  assert.throws(
    () =>
      loadVaultState(account(), {
        expected: {
          plaintext: JSON.stringify({ id: "substituted", type: "login", title: "Bad", updatedAt: 1 }),
        },
      }),
    VaultIntegrityError
  );
});

test("rejects malformed reserved state", () => {
  assert.throws(
    () => loadVaultState(account(), { "bastion:send-contacts": { plaintext: "{}" } }),
    VaultIntegrityError
  );
});

test("rejects an item with a non-string secret field", () => {
  assert.throws(
    () =>
      loadVaultState(account(), {
        item1: {
          plaintext: JSON.stringify({
            id: "item1",
            type: "login",
            title: "Bad",
            password: { injected: true },
            updatedAt: 1,
          }),
        },
      }),
    VaultIntegrityError
  );
});
