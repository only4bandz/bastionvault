import assert from "node:assert/strict";
import test from "node:test";

import {
  VaultRollbackError,
  assertVaultRollbackProgress,
  createVaultRollbackAnchor,
  readVaultRollbackAnchor,
  vaultRollbackAnchorKey,
  withVaultRollbackLock,
  writeVaultRollbackAnchor,
} from "../lib/vault-anchor.js";

function memoryArea() {
  const values = new Map();
  return {
    values,
    async get(key) {
      return values.has(key) ? { [key]: structuredClone(values.get(key)) } : {};
    },
    async set(entries) {
      for (const [key, value] of Object.entries(entries)) {
        values.set(key, structuredClone(value));
      }
    },
  };
}

const integrity = (revision, manifestSeq, manifestJson) => ({
  revision,
  manifestSeq,
  manifestJson,
  encryptedItems: {},
});

test("persists a strict checkpoint scoped by server and account", async () => {
  const area = memoryArea();
  const alice = vaultRollbackAnchorKey("https://vault.example", "alice@example.com");
  const bob = vaultRollbackAnchorKey("https://vault.example", "bob@example.com");
  assert.notEqual(alice, bob);

  const anchor = await createVaultRollbackAnchor(integrity(7, 11n, '{"seq":11}'));
  await writeVaultRollbackAnchor(area, alice, anchor);
  assert.deepEqual(await readVaultRollbackAnchor(area, alice), anchor);
  assert.equal(await readVaultRollbackAnchor(area, bob), null);
});

test("rejects revision rollback, sequence rollback, and same-sequence substitution", async () => {
  const trusted = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12,"a":1}'));
  const oldRevision = await createVaultRollbackAnchor(integrity(7, 12n, '{"seq":12,"a":1}'));
  const oldSequence = await createVaultRollbackAnchor(integrity(9, 11n, '{"seq":11}'));
  const substitute = await createVaultRollbackAnchor(integrity(9, 12n, '{"seq":12,"b":1}'));

  assert.throws(() => assertVaultRollbackProgress(oldRevision, trusted), VaultRollbackError);
  assert.throws(() => assertVaultRollbackProgress(oldSequence, trusted), VaultRollbackError);
  assert.throws(
    () => assertVaultRollbackProgress(substitute, trusted),
    /manifest conflicts/i
  );
});

test("rejects same-revision sequence conflicts and stale checkpoint writers", async () => {
  const area = memoryArea();
  const key = vaultRollbackAnchorKey("https://vault.example", "alice@example.com");
  const revisionEight = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12}'));
  const revisionNine = await createVaultRollbackAnchor(integrity(9, 13n, '{"seq":13}'));
  const inconsistent = await createVaultRollbackAnchor(integrity(8, 13n, '{"seq":13}'));

  assert.throws(
    () => assertVaultRollbackProgress(inconsistent, revisionEight),
    /revision conflicts/i
  );
  await writeVaultRollbackAnchor(area, key, revisionNine);
  await assert.rejects(() => writeVaultRollbackAnchor(area, key, revisionEight), /rollback/i);
  assert.deepEqual(await readVaultRollbackAnchor(area, key), revisionNine);
});

test("fails closed on non-canonical and out-of-range checkpoint data", async () => {
  const area = memoryArea();
  const key = vaultRollbackAnchorKey("https://vault.example", "alice@example.com");
  area.values.set(key, {
    version: 1,
    revision: 1,
    manifest_seq: "01",
    manifest_digest: "a".repeat(64),
  });
  await assert.rejects(() => readVaultRollbackAnchor(area, key), /corrupted/i);

  area.values.set(key, {
    version: 1,
    revision: 1,
    manifest_seq: "18446744073709551616",
    manifest_digest: "a".repeat(64),
  });
  await assert.rejects(() => readVaultRollbackAnchor(area, key), /corrupted/i);
});

test("serializes checkpoint work inside the service worker", async () => {
  const order = [];
  const first = withVaultRollbackLock("same", async () => {
    order.push("first-start");
    await Promise.resolve();
    order.push("first-end");
  });
  const second = withVaultRollbackLock("same", async () => {
    order.push("second");
  });
  await Promise.all([first, second]);
  assert.deepEqual(order, ["first-start", "first-end", "second"]);
});
