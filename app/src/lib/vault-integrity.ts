import type { Blob, VaultData, VaultOperation } from "./api";
import type { Account } from "./wasm";

export type IntegrityAccount = Pick<
  Account,
  | "check_manifest"
  | "manifest_from_items"
  | "manifest_remove_item"
  | "manifest_seq"
  | "manifest_set_item"
  | "open_manifest"
  | "open_manifest_checked"
  | "seal_manifest"
>;

export interface VaultIntegrityState {
  revision: number;
  manifestJson: string;
  manifestSeq: bigint;
  encryptedItems: Record<string, Blob>;
}

export interface PreparedVaultMutation {
  operations: VaultOperation[];
  manifest: Blob;
  manifestJson: string;
  encryptedItems: Record<string, Blob>;
}

export interface BootstrapManifest {
  manifest: Blob;
  manifestJson: string;
}

function requireSafeRevision(revision: number): void {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new Error("Invalid vault revision.");
  }
}

function parseBlob(json: string): Blob {
  const blob: unknown = JSON.parse(json);
  if (
    !blob ||
    typeof blob !== "object" ||
    typeof (blob as Blob).v !== "number" ||
    typeof (blob as Blob).nonce !== "string" ||
    typeof (blob as Blob).ct !== "string"
  ) {
    throw new Error("Invalid encrypted manifest.");
  }
  return blob as Blob;
}

function requireIntactReport(reportJson: string): void {
  const report: unknown = JSON.parse(reportJson);
  const fields = ["missing", "unexpected", "corrupted", "duplicates"] as const;
  if (
    !report ||
    typeof report !== "object" ||
    fields.some(
      (field) =>
        !Array.isArray((report as Record<string, unknown>)[field]) ||
        ((report as Record<string, unknown>)[field] as unknown[]).length !== 0
    )
  ) {
    throw new Error("Encrypted vault integrity check failed.");
  }
}

function encryptedItemsEqual(
  left: Record<string, Blob>,
  right: Record<string, Blob>
): boolean {
  const leftIds = Object.keys(left).sort();
  const rightIds = Object.keys(right).sort();
  return (
    leftIds.length === rightIds.length &&
    leftIds.every((id, index) => {
      const a = left[id];
      const b = right[rightIds[index]];
      return id === rightIds[index] && a.v === b.v && a.nonce === b.nonce && a.ct === b.ct;
    })
  );
}

/** Open and verify the complete encrypted item set before any item decryption. */
export function verifyVaultSnapshot(
  account: IntegrityAccount,
  vault: VaultData,
  lastSeenSeq?: bigint
): VaultIntegrityState {
  requireSafeRevision(vault.revision);
  if (!vault.manifest) throw new Error("Vault integrity manifest is missing.");
  const sealedJson = JSON.stringify(vault.manifest);
  const manifestJson =
    lastSeenSeq === undefined
      ? account.open_manifest(sealedJson)
      : account.open_manifest_checked(sealedJson, lastSeenSeq);
  requireIntactReport(account.check_manifest(manifestJson, JSON.stringify(vault.items)));
  return {
    revision: vault.revision,
    manifestJson,
    manifestSeq: account.manifest_seq(manifestJson),
    encryptedItems: { ...vault.items },
  };
}

/** Create the one-time TOFU manifest for a fully decrypted legacy vault. */
export function prepareBootstrapManifest(
  account: IntegrityAccount,
  vault: VaultData
): BootstrapManifest {
  requireSafeRevision(vault.revision);
  if (vault.manifest) throw new Error("Vault already has an integrity manifest.");
  const manifestJson = account.manifest_from_items(JSON.stringify(vault.items));
  requireIntactReport(account.check_manifest(manifestJson, JSON.stringify(vault.items)));
  return {
    manifestJson,
    manifest: parseBlob(account.seal_manifest(manifestJson)),
  };
}

export function completeBootstrap(
  account: IntegrityAccount,
  vault: VaultData,
  bootstrap: BootstrapManifest,
  revision: number
): VaultIntegrityState {
  requireSafeRevision(revision);
  if (revision !== vault.revision + 1) throw new Error("Invalid vault transaction revision.");
  return {
    revision,
    manifestJson: bootstrap.manifestJson,
    manifestSeq: account.manifest_seq(bootstrap.manifestJson),
    encryptedItems: { ...vault.items },
  };
}

/** Apply item operations to a validated manifest entirely inside WASM. */
export function prepareVaultMutation(
  account: IntegrityAccount,
  current: VaultIntegrityState,
  operations: VaultOperation[]
): PreparedVaultMutation {
  if (operations.length === 0) throw new Error("Vault mutation is empty.");
  const seen = new Set<string>();
  const encryptedItems = { ...current.encryptedItems };
  let manifestJson = current.manifestJson;
  for (const operation of operations) {
    if (seen.has(operation.id)) throw new Error("Duplicate vault item operation.");
    seen.add(operation.id);
    if (operation.op === "put") {
      manifestJson = account.manifest_set_item(
        manifestJson,
        operation.id,
        JSON.stringify(operation.blob)
      );
      encryptedItems[operation.id] = operation.blob;
    } else {
      manifestJson = account.manifest_remove_item(manifestJson, operation.id);
      delete encryptedItems[operation.id];
    }
  }
  requireIntactReport(account.check_manifest(manifestJson, JSON.stringify(encryptedItems)));
  return {
    operations,
    manifestJson,
    manifest: parseBlob(account.seal_manifest(manifestJson)),
    encryptedItems,
  };
}

export function completeVaultMutation(
  account: IntegrityAccount,
  current: VaultIntegrityState,
  prepared: PreparedVaultMutation,
  revision: number
): VaultIntegrityState {
  requireSafeRevision(revision);
  if (revision !== current.revision + 1) throw new Error("Invalid vault transaction revision.");
  return {
    revision,
    manifestJson: prepared.manifestJson,
    manifestSeq: account.manifest_seq(prepared.manifestJson),
    encryptedItems: prepared.encryptedItems,
  };
}

/**
 * Positively confirm an ambiguous transaction from a fresh server snapshot.
 * A current or unrelated snapshot is never interpreted as proof of failure:
 * the original request may still be completing on another connection.
 */
export function reconcileVaultMutation(
  account: IntegrityAccount,
  current: VaultIntegrityState,
  prepared: PreparedVaultMutation,
  vault: VaultData
): VaultIntegrityState | null {
  const verified = verifyVaultSnapshot(account, vault, current.manifestSeq);
  if (
    verified.revision !== current.revision + 1 ||
    verified.manifestJson !== prepared.manifestJson ||
    !encryptedItemsEqual(verified.encryptedItems, prepared.encryptedItems)
  ) {
    return null;
  }
  return completeVaultMutation(account, current, prepared, verified.revision);
}
