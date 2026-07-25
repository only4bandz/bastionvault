import { requireContactsPayload } from "./send-contact-state.js";
import { isVaultItemPayload } from "./vault-item-state.js";

const SEND_IDENTITY_ID = "bastion:send-identity";
const SEND_CONTACTS_ID = "bastion:send-contacts";
const SEND_LOCKED_PREFIX = "bastion:send-locked:";
const SEND_RESERVED_PREFIX = "bastion:send-";

export class VaultIntegrityError extends Error {
  constructor() {
    super("Encrypted vault integrity check failed. No items were loaded.");
    this.name = "VaultIntegrityError";
  }
}

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);

function requireSafeRevision(revision) {
  if (!Number.isSafeInteger(revision) || revision < 0) throw new VaultIntegrityError();
}

/** Decide whether a previously verified snapshot needs a full refetch. */
export function vaultRefreshRequired(currentRevision, remoteRevision) {
  requireSafeRevision(currentRevision);
  requireSafeRevision(remoteRevision);
  if (remoteRevision < currentRevision) throw new VaultIntegrityError();
  return remoteRevision > currentRevision;
}

function parseBlob(json) {
  const blob = JSON.parse(json);
  if (!isRecord(blob) || typeof blob.v !== "number" || typeof blob.nonce !== "string" || typeof blob.ct !== "string") {
    throw new VaultIntegrityError();
  }
  return blob;
}

function requireIntactReport(reportJson) {
  const report = JSON.parse(reportJson);
  if (
    !isRecord(report) ||
    ["missing", "unexpected", "corrupted", "duplicates"].some(
      (field) => !Array.isArray(report[field]) || report[field].length !== 0
    )
  ) {
    throw new VaultIntegrityError();
  }
}

function decryptVaultItems(account, rawItems) {
  if (!isRecord(rawItems)) throw new VaultIntegrityError();
  const items = new Map();
  let contacts = [];
  const lockedRecords = [];
  for (const [id, blob] of Object.entries(rawItems)) {
    if (id === SEND_IDENTITY_ID) {
      account.load_send_identity(JSON.stringify(blob));
      continue;
    }

    const plaintext = account.decrypt_item(JSON.stringify(blob), id);
    const parsed = JSON.parse(plaintext);
    if (id === SEND_CONTACTS_ID) {
      contacts = requireContactsPayload(parsed);
    } else if (id.startsWith(SEND_LOCKED_PREFIX)) {
      if (!isRecord(parsed)) throw new VaultIntegrityError();
      lockedRecords.push(parsed);
    } else if (id.startsWith(SEND_RESERVED_PREFIX)) {
      throw new VaultIntegrityError();
    } else {
      if (!isVaultItemPayload(parsed, id)) throw new VaultIntegrityError();
      if (parsed.deletedAt === undefined) items.set(id, parsed);
    }
  }
  return { items, contacts, lockedRecords };
}

export function verifyVaultSnapshot(account, vault, { lastSeenSeq, minimumRevision } = {}) {
  try {
    if (!isRecord(vault) || !isRecord(vault.items) || !isRecord(vault.manifest)) {
      throw new VaultIntegrityError();
    }
    requireSafeRevision(vault.revision);
    if (minimumRevision !== undefined) {
      requireSafeRevision(minimumRevision);
      if (vault.revision < minimumRevision) throw new VaultIntegrityError();
    }
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
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

/** Decrypt only the exact encrypted set covered by a previously verified snapshot. */
export function decryptVerifiedVaultState(account, vault, integrity) {
  try {
    if (
      !isRecord(vault) ||
      !isRecord(vault.items) ||
      !isRecord(integrity) ||
      integrity.revision !== vault.revision ||
      !encryptedItemsEqual(integrity.encryptedItems, vault.items)
    ) {
      throw new VaultIntegrityError();
    }
    return decryptVaultItems(account, vault.items);
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

/** Verify manifest + complete encrypted set before decrypting any item. */
export function loadVaultState(account, vault, options = {}) {
  try {
    const integrity = verifyVaultSnapshot(account, vault, options);
    const decrypted = decryptVerifiedVaultState(account, vault, integrity);
    return { ...decrypted, integrity };
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

/** Decrypt a legacy manifest-less vault before its one-time TOFU bootstrap. */
export function loadLegacyVaultState(account, vault) {
  try {
    if (!isRecord(vault) || !isRecord(vault.items) || vault.manifest !== null) {
      throw new VaultIntegrityError();
    }
    requireSafeRevision(vault.revision);
    return decryptVaultItems(account, vault.items);
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

export function prepareBootstrapManifest(account, vault) {
  try {
    if (!isRecord(vault) || !isRecord(vault.items) || vault.manifest !== null) {
      throw new VaultIntegrityError();
    }
    requireSafeRevision(vault.revision);
    const manifestJson = account.manifest_from_items(JSON.stringify(vault.items));
    requireIntactReport(account.check_manifest(manifestJson, JSON.stringify(vault.items)));
    return { manifestJson, manifest: parseBlob(account.seal_manifest(manifestJson)) };
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

export function completeBootstrap(account, vault, bootstrap, revision) {
  try {
    requireSafeRevision(revision);
    if (revision !== vault.revision + 1) throw new VaultIntegrityError();
    return {
      revision,
      manifestJson: bootstrap.manifestJson,
      manifestSeq: account.manifest_seq(bootstrap.manifestJson),
      encryptedItems: { ...vault.items },
    };
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

export function prepareVaultMutation(account, current, operations) {
  try {
    if (!operations.length) throw new VaultIntegrityError();
    const seen = new Set();
    const encryptedItems = { ...current.encryptedItems };
    let manifestJson = current.manifestJson;
    for (const operation of operations) {
      if (!isRecord(operation) || typeof operation.id !== "string" || seen.has(operation.id)) {
        throw new VaultIntegrityError();
      }
      seen.add(operation.id);
      if (operation.op === "put") {
        manifestJson = account.manifest_set_item(manifestJson, operation.id, JSON.stringify(operation.blob));
        encryptedItems[operation.id] = operation.blob;
      } else if (operation.op === "delete") {
        manifestJson = account.manifest_remove_item(manifestJson, operation.id);
        delete encryptedItems[operation.id];
      } else {
        throw new VaultIntegrityError();
      }
    }
    requireIntactReport(account.check_manifest(manifestJson, JSON.stringify(encryptedItems)));
    return {
      operations,
      manifestJson,
      manifest: parseBlob(account.seal_manifest(manifestJson)),
      encryptedItems,
    };
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

export function completeVaultMutation(account, current, prepared, revision) {
  try {
    requireSafeRevision(revision);
    if (revision !== current.revision + 1) throw new VaultIntegrityError();
    return {
      revision,
      manifestJson: prepared.manifestJson,
      manifestSeq: account.manifest_seq(prepared.manifestJson),
      encryptedItems: prepared.encryptedItems,
    };
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}

function encryptedItemsEqual(left, right) {
  const leftIds = Object.keys(left).sort();
  const rightIds = Object.keys(right).sort();
  return (
    leftIds.length === rightIds.length &&
    leftIds.every((id, index) => {
      const a = left[id];
      const b = right[rightIds[index]];
      return (
        id === rightIds[index] &&
        isRecord(a) &&
        isRecord(b) &&
        a.v === b.v &&
        a.nonce === b.nonce &&
        a.ct === b.ct
      );
    })
  );
}

/** Positively confirm an ambiguous transaction without decrypting item data. */
export function reconcileVaultMutation(account, current, prepared, vault) {
  try {
    const verified = verifyVaultSnapshot(account, vault, {
      lastSeenSeq: current.manifestSeq,
      minimumRevision: current.revision,
    });
    if (
      verified.revision !== current.revision + 1 ||
      verified.manifestJson !== prepared.manifestJson ||
      !encryptedItemsEqual(verified.encryptedItems, prepared.encryptedItems)
    ) {
      return null;
    }
    return completeVaultMutation(account, current, prepared, verified.revision);
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
}
