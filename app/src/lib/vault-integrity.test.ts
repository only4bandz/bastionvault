import { describe, expect, it } from "vitest";
import type { Blob, VaultData, VaultOperation } from "./api";
import {
  completeBootstrap,
  completeVaultMutation,
  prepareBootstrapManifest,
  prepareVaultMutation,
  verifyVaultSnapshot,
  type IntegrityAccount,
} from "./vault-integrity";

type TestManifest = { seq: number; entries: Record<string, string> };

const blob = (ct: string): Blob => ({ v: 1, nonce: "nonce", ct });

function testAccount(): IntegrityAccount {
  const parse = (json: string): TestManifest => JSON.parse(json) as TestManifest;
  const seal = (manifestJson: string): string => JSON.stringify(blob(manifestJson));
  const open = (sealedJson: string): string => (JSON.parse(sealedJson) as Blob).ct;
  return {
    check_manifest(manifestJson, itemsJson) {
      const manifest = parse(manifestJson);
      const items = JSON.parse(itemsJson) as Record<string, Blob>;
      const expected = Object.keys(manifest.entries);
      const present = Object.keys(items);
      return JSON.stringify({
        missing: expected.filter((id) => !(id in items)),
        unexpected: present.filter((id) => !(id in manifest.entries)),
        corrupted: expected.filter(
          (id) => id in items && manifest.entries[id] !== items[id].ct
        ),
        duplicates: [],
      });
    },
    manifest_from_items(itemsJson) {
      const items = JSON.parse(itemsJson) as Record<string, Blob>;
      return JSON.stringify({
        seq: Object.keys(items).length,
        entries: Object.fromEntries(
          Object.keys(items)
            .sort()
            .map((id) => [id, items[id].ct])
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
      manifest.entries[itemId] = (JSON.parse(blobJson) as Blob).ct;
      manifest.seq += 1;
      return JSON.stringify(manifest);
    },
    open_manifest: open,
    open_manifest_checked(sealedJson, lastSeenSeq) {
      const manifestJson = open(sealedJson);
      if (BigInt(parse(manifestJson).seq) < lastSeenSeq) throw new Error("rollback");
      return manifestJson;
    },
    seal_manifest: seal,
  };
}

function vault(
  account: IntegrityAccount,
  items: Record<string, Blob>,
  revision = 0
): VaultData {
  const manifestJson = account.manifest_from_items(JSON.stringify(items));
  return {
    items,
    manifest: JSON.parse(account.seal_manifest(manifestJson)) as Blob,
    revision,
  };
}

describe("vault integrity state", () => {
  it("opens and checks the complete encrypted set", () => {
    const account = testAccount();
    const snapshot = vault(account, { a: blob("a"), b: blob("b") }, 4);
    const verified = verifyVaultSnapshot(account, snapshot);
    expect(verified.revision).toBe(4);
    expect(verified.manifestSeq).toBe(2n);
    expect(verified.encryptedItems).toEqual(snapshot.items);

    snapshot.items.b = blob("substituted");
    expect(() => verifyVaultSnapshot(account, snapshot)).toThrow(/integrity/i);
  });

  it("rejects a rollback against the in-memory manifest sequence", () => {
    const account = testAccount();
    const snapshot = vault(account, { a: blob("a") }, 1);
    expect(() => verifyVaultSnapshot(account, snapshot, 2n)).toThrow("rollback");
  });

  it("bootstraps a legacy snapshot only at the next exact revision", () => {
    const account = testAccount();
    const legacy: VaultData = { items: { a: blob("a") }, manifest: null, revision: 7 };
    const bootstrap = prepareBootstrapManifest(account, legacy);
    const completed = completeBootstrap(account, legacy, bootstrap, 8);
    expect(completed.revision).toBe(8);
    expect(completed.manifestSeq).toBe(1n);
    expect(() => completeBootstrap(account, legacy, bootstrap, 9)).toThrow(/revision/i);
  });

  it("prepares deterministic put/delete changes without mutating current state", () => {
    const account = testAccount();
    const current = verifyVaultSnapshot(account, vault(account, { a: blob("a") }, 2));
    const operations: VaultOperation[] = [
      { op: "put", id: "b", blob: blob("b") },
      { op: "delete", id: "a" },
    ];
    const prepared = prepareVaultMutation(account, current, operations);
    expect(current.encryptedItems).toEqual({ a: blob("a") });
    expect(prepared.encryptedItems).toEqual({ b: blob("b") });
    const completed = completeVaultMutation(account, current, prepared, 3);
    expect(completed.revision).toBe(3);
    expect(completed.manifestSeq).toBe(3n);
  });

  it("rejects duplicate operations and unsafe revisions", () => {
    const account = testAccount();
    const current = verifyVaultSnapshot(account, vault(account, {}, 0));
    expect(() =>
      prepareVaultMutation(account, current, [
        { op: "put", id: "same", blob: blob("one") },
        { op: "delete", id: "same" },
      ])
    ).toThrow(/duplicate/i);
    expect(() => verifyVaultSnapshot(account, { ...vault(account, {}), revision: 2 ** 53 }))
      .toThrow(/revision/i);
  });
});
