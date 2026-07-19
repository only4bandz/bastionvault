import assert from "node:assert/strict";
import test from "node:test";

import {
  completeBootstrap,
  completeVaultMutation,
  decryptVerifiedVaultState,
  loadLegacyVaultState,
  loadVaultState,
  prepareBootstrapManifest,
  prepareVaultMutation,
  reconcileVaultMutation,
  verifyVaultSnapshot,
  VaultIntegrityError,
} from "../lib/vault-load.js";

const digest = (blob) => JSON.stringify(blob);

function account() {
  const parse = (json) => JSON.parse(json);
  const open = (sealedJson) => parse(sealedJson).ct;
  return {
    check_manifest(manifestJson, itemsJson) {
      const manifest = parse(manifestJson);
      const items = parse(itemsJson);
      const expected = Object.keys(manifest.entries);
      const present = Object.keys(items);
      return JSON.stringify({
        missing: expected.filter((id) => !(id in items)),
        unexpected: present.filter((id) => !(id in manifest.entries)),
        corrupted: expected.filter(
          (id) => id in items && manifest.entries[id] !== digest(items[id])
        ),
        duplicates: [],
      });
    },
    manifest_from_items(itemsJson) {
      const items = parse(itemsJson);
      return JSON.stringify({
        seq: Object.keys(items).length,
        entries: Object.fromEntries(
          Object.keys(items)
            .sort()
            .map((id) => [id, digest(items[id])])
        ),
      });
    },
    manifest_remove_item(manifestJson, itemId) {
      const manifest = parse(manifestJson);
      if (itemId in manifest.entries) {
        delete manifest.entries[itemId];
        manifest.seq += 1;
      }
      return JSON.stringify(manifest);
    },
    manifest_seq(manifestJson) {
      return BigInt(parse(manifestJson).seq);
    },
    manifest_set_item(manifestJson, itemId, blobJson) {
      const manifest = parse(manifestJson);
      manifest.entries[itemId] = digest(parse(blobJson));
      manifest.seq += 1;
      return JSON.stringify(manifest);
    },
    open_manifest: open,
    open_manifest_checked(sealedJson, lastSeenSeq) {
      const manifestJson = open(sealedJson);
      if (BigInt(parse(manifestJson).seq) < lastSeenSeq) throw new Error("rollback");
      return manifestJson;
    },
    seal_manifest(manifestJson) {
      return JSON.stringify({ v: 1, nonce: "nonce", ct: manifestJson });
    },
    load_send_identity(blob) {
      if (parse(blob).corrupt) throw new Error("bad identity");
    },
    decrypt_item(blob) {
      const value = parse(blob);
      if (value.corrupt) throw new Error("bad ciphertext");
      return value.plaintext;
    },
  };
}

function snapshot(acc, items, revision = 0) {
  const manifestJson = acc.manifest_from_items(JSON.stringify(items));
  return {
    items,
    manifest: JSON.parse(acc.seal_manifest(manifestJson)),
    revision,
  };
}

test("verifies the manifest before loading a complete valid vault", () => {
  const acc = account();
  const result = loadVaultState(
    acc,
    snapshot(acc, {
      item1: {
        plaintext: JSON.stringify({ id: "item1", type: "login", title: "Example", updatedAt: 1 }),
      },
      "bastion:send-contacts": { plaintext: "[]" },
    }, 4)
  );
  assert.equal(result.items.size, 1);
  assert.deepEqual(result.contacts, []);
  assert.equal(result.integrity.revision, 4);
  assert.equal(result.integrity.manifestSeq, 2n);
});

test("validates but withholds trashed items from every extension consumer", () => {
  const acc = account();
  const result = loadVaultState(
    acc,
    snapshot(acc, {
      active: {
        plaintext: JSON.stringify({ id: "active", type: "login", title: "Active", folder: "Personal", updatedAt: 1 }),
      },
      deleted: {
        plaintext: JSON.stringify({ id: "deleted", type: "login", title: "Deleted", deletedAt: 2, updatedAt: 2 }),
      },
    })
  );
  assert.deepEqual([...result.items.keys()], ["active"]);
  assert.ok("deleted" in result.integrity.encryptedItems);
});

test("fails before decryption when the encrypted set differs from the manifest", () => {
  const acc = account();
  let decryptions = 0;
  const decrypt = acc.decrypt_item;
  acc.decrypt_item = (...args) => {
    decryptions += 1;
    return decrypt(...args);
  };
  const vault = snapshot(acc, {
    good: { plaintext: JSON.stringify({ id: "good", type: "note", title: "Good", updatedAt: 1 }) },
  });
  vault.items.injected = {
    plaintext: JSON.stringify({ id: "injected", type: "note", title: "Bad", updatedAt: 1 }),
  };
  assert.throws(() => loadVaultState(acc, vault), VaultIntegrityError);
  assert.equal(decryptions, 0);
});

test("rejects rollback against a trusted checkpoint", () => {
  const acc = account();
  const vault = snapshot(acc, {}, 3);
  assert.throws(
    () => loadVaultState(acc, vault, { lastSeenSeq: 1n, minimumRevision: 4 }),
    VaultIntegrityError
  );
  assert.throws(
    () => loadVaultState(acc, vault, { lastSeenSeq: 1n, minimumRevision: 3 }),
    VaultIntegrityError
  );
});

test("refuses to decrypt a snapshot different from the verified encrypted set", () => {
  const acc = account();
  let decryptions = 0;
  const decrypt = acc.decrypt_item;
  acc.decrypt_item = (...args) => {
    decryptions += 1;
    return decrypt(...args);
  };
  const verifiedVault = snapshot(acc, {
    item1: {
      plaintext: JSON.stringify({ id: "item1", type: "note", title: "One", updatedAt: 1 }),
    },
  }, 4);
  const integrity = verifyVaultSnapshot(acc, verifiedVault);
  const substituted = {
    ...verifiedVault,
    items: {
      item2: {
        plaintext: JSON.stringify({ id: "item2", type: "note", title: "Two", updatedAt: 2 }),
      },
    },
  };
  assert.throws(
    () => decryptVerifiedVaultState(acc, substituted, integrity),
    VaultIntegrityError
  );
  assert.equal(decryptions, 0);
});

test("bootstraps a fully validated legacy vault at the exact next revision", () => {
  const acc = account();
  const legacy = {
    items: {
      item1: {
        plaintext: JSON.stringify({ id: "item1", type: "login", title: "Example", updatedAt: 1 }),
      },
    },
    manifest: null,
    revision: 7,
  };
  const loaded = loadLegacyVaultState(acc, legacy);
  assert.equal(loaded.items.size, 1);
  const bootstrap = prepareBootstrapManifest(acc, legacy);
  const completed = completeBootstrap(acc, legacy, bootstrap, 8);
  assert.equal(completed.revision, 8);
  assert.equal(completed.manifestSeq, 1n);
  assert.throws(() => completeBootstrap(acc, legacy, bootstrap, 9), VaultIntegrityError);
});

test("prepares copy-on-write manifest mutations and rejects duplicates", () => {
  const acc = account();
  const current = loadVaultState(
    acc,
    snapshot(acc, {
      old: { plaintext: JSON.stringify({ id: "old", type: "note", title: "Old", updatedAt: 1 }) },
    }, 2)
  ).integrity;
  const nextBlob = {
    plaintext: JSON.stringify({ id: "new", type: "note", title: "New", updatedAt: 2 }),
  };
  const prepared = prepareVaultMutation(acc, current, [
    { op: "put", id: "new", blob: nextBlob },
    { op: "delete", id: "old" },
  ]);
  assert.deepEqual(Object.keys(current.encryptedItems), ["old"]);
  assert.deepEqual(Object.keys(prepared.encryptedItems), ["new"]);
  const completed = completeVaultMutation(acc, current, prepared, 3);
  assert.equal(completed.manifestSeq, 3n);
  assert.throws(
    () =>
      prepareVaultMutation(acc, current, [
        { op: "put", id: "same", blob: nextBlob },
        { op: "delete", id: "same" },
      ]),
    VaultIntegrityError
  );
});

test("reconciles only the exact ambiguous mutation without decrypting items", () => {
  const acc = account();
  let decryptions = 0;
  const decrypt = acc.decrypt_item;
  acc.decrypt_item = (...args) => {
    decryptions += 1;
    return decrypt(...args);
  };
  const oldBlob = {
    v: 1,
    nonce: "old-nonce",
    ct: "old-ct",
    plaintext: JSON.stringify({ id: "old", type: "note", title: "Old", updatedAt: 1 }),
  };
  const nextBlob = {
    v: 1,
    nonce: "next-nonce",
    ct: "next-ct",
    plaintext: JSON.stringify({ id: "next", type: "note", title: "Next", updatedAt: 2 }),
  };
  const original = snapshot(acc, { old: oldBlob }, 2);
  const current = loadVaultState(acc, original).integrity;
  const prepared = prepareVaultMutation(acc, current, [
    { op: "put", id: "next", blob: nextBlob },
  ]);
  decryptions = 0;

  const committed = {
    // Object order can differ after server HashMap serialization.
    items: { next: nextBlob, old: oldBlob },
    manifest: prepared.manifest,
    revision: 3,
  };
  const reconciled = reconcileVaultMutation(acc, current, prepared, committed);
  assert.equal(reconciled.revision, 3);
  assert.equal(decryptions, 0);

  assert.equal(reconcileVaultMutation(acc, current, prepared, original), null);

  const competing = prepareVaultMutation(acc, current, [
    { op: "delete", id: "old" },
  ]);
  assert.equal(
    reconcileVaultMutation(acc, current, prepared, {
      items: competing.encryptedItems,
      manifest: competing.manifest,
      revision: 3,
    }),
    null
  );

  assert.throws(
    () =>
      reconcileVaultMutation(acc, current, prepared, {
        ...committed,
        items: { ...committed.items, next: { ...nextBlob, ct: "tampered" } },
      }),
    VaultIntegrityError
  );
});

test("fails the entire legacy load on invalid plaintext or reserved state", () => {
  const acc = account();
  assert.throws(
    () =>
      loadLegacyVaultState(acc, {
        items: { expected: { plaintext: JSON.stringify({ id: "substituted", type: "login", title: "Bad", updatedAt: 1 }) } },
        manifest: null,
        revision: 0,
      }),
    VaultIntegrityError
  );
  assert.throws(
    () =>
      loadLegacyVaultState(acc, {
        items: { "bastion:send-contacts": { plaintext: "{}" } },
        manifest: null,
        revision: 0,
      }),
    VaultIntegrityError
  );
});
