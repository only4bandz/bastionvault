import { describe, expect, it } from "vitest";
import type { VaultIntegrityState } from "./vault-integrity";
import {
  VaultRollbackError,
  assertVaultRollbackProgress,
  createVaultRollbackAnchor,
  readVaultRollbackAnchor,
  vaultRollbackAnchorKey,
  writeVaultRollbackAnchor,
  type AnchorStorage,
} from "./vault-anchor";

function memoryStore(): AnchorStorage & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
  };
}

function integrity(
  revision: number,
  manifestSeq: bigint,
  manifestJson: string
): VaultIntegrityState {
  return { revision, manifestSeq, manifestJson, encryptedItems: {} };
}

describe("persistent vault rollback anchors", () => {
  it("scopes checkpoints by API and account and round-trips strict data", async () => {
    const store = memoryStore();
    const firstKey = vaultRollbackAnchorKey("https://vault.example/api", "alice@example.com");
    const otherKey = vaultRollbackAnchorKey("https://vault.example/api", "bob@example.com");
    expect(firstKey).not.toBe(otherKey);

    const anchor = await createVaultRollbackAnchor(integrity(7, 11n, '{"seq":11}'));
    writeVaultRollbackAnchor(store, firstKey, anchor);
    expect(readVaultRollbackAnchor(store, firstKey)).toEqual(anchor);
    expect(readVaultRollbackAnchor(store, otherKey)).toBeNull();
  });

  it("rejects revision and manifest-sequence rollback", async () => {
    const trusted = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12}'));
    const oldRevision = await createVaultRollbackAnchor(integrity(7, 12n, '{"seq":12}'));
    const oldSequence = await createVaultRollbackAnchor(integrity(9, 11n, '{"seq":11}'));
    expect(() => assertVaultRollbackProgress(oldRevision, trusted)).toThrow(VaultRollbackError);
    expect(() => assertVaultRollbackProgress(oldSequence, trusted)).toThrow(VaultRollbackError);
  });

  it("rejects equal-sequence manifest substitution even at a higher revision", async () => {
    const trusted = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12,"a":1}'));
    const substitute = await createVaultRollbackAnchor(integrity(9, 12n, '{"seq":12,"b":1}'));
    expect(() => assertVaultRollbackProgress(substitute, trusted)).toThrow(/manifest conflicts/i);
  });

  it("rejects a changed sequence at the same server revision", async () => {
    const trusted = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12}'));
    const inconsistent = await createVaultRollbackAnchor(integrity(8, 13n, '{"seq":13}'));
    expect(() => assertVaultRollbackProgress(inconsistent, trusted)).toThrow(/revision conflicts/i);
  });

  it("rechecks the latest stored checkpoint before advancing", async () => {
    const store = memoryStore();
    const key = vaultRollbackAnchorKey("https://vault.example/api", "alice@example.com");
    const revisionEight = await createVaultRollbackAnchor(integrity(8, 12n, '{"seq":12}'));
    const revisionNine = await createVaultRollbackAnchor(integrity(9, 13n, '{"seq":13}'));
    writeVaultRollbackAnchor(store, key, revisionNine);
    expect(() => writeVaultRollbackAnchor(store, key, revisionEight)).toThrow(/rollback/i);
    expect(readVaultRollbackAnchor(store, key)).toEqual(revisionNine);
  });

  it("fails closed on corrupted or non-canonical stored data", () => {
    const store = memoryStore();
    const key = vaultRollbackAnchorKey("https://vault.example/api", "alice@example.com");
    store.values.set(
      key,
      JSON.stringify({
        version: 1,
        revision: 1,
        manifest_seq: "01",
        manifest_digest: "a".repeat(64),
      })
    );
    expect(() => readVaultRollbackAnchor(store, key)).toThrow(/corrupted/i);

    store.values.set(
      key,
      JSON.stringify({
        version: 1,
        revision: 1,
        manifest_seq: "18446744073709551616",
        manifest_digest: "a".repeat(64),
      })
    );
    expect(() => readVaultRollbackAnchor(store, key)).toThrow(/corrupted/i);
  });
});
