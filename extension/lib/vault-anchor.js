const ANCHOR_VERSION = 1;
const ANCHOR_PREFIX = "bastion:vault-rollback-anchor:v1";
const MAX_MANIFEST_SEQ = (1n << 64n) - 1n;
const RECOVERY_GUIDANCE =
  "Restore the latest server state. To intentionally trust a verified recovery snapshot, reset this extension's stored data first.";
const anchorLocks = new Map();

export class VaultRollbackError extends Error {
  constructor(message) {
    super(`${message} ${RECOVERY_GUIDANCE}`);
    this.name = "VaultRollbackError";
  }
}

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);

function requireRevision(revision) {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new VaultRollbackError("The trusted vault revision is invalid.");
  }
}

function parseAnchor(value) {
  const keys = isRecord(value) ? Object.keys(value).sort() : [];
  const expectedKeys = ["manifest_digest", "manifest_seq", "revision", "version"];
  if (
    keys.length !== expectedKeys.length ||
    keys.some((key, index) => key !== expectedKeys[index]) ||
    value.version !== ANCHOR_VERSION ||
    typeof value.revision !== "number" ||
    typeof value.manifest_seq !== "string" ||
    !/^(0|[1-9][0-9]{0,19})$/.test(value.manifest_seq) ||
    typeof value.manifest_digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(value.manifest_digest)
  ) {
    throw new VaultRollbackError("The trusted vault rollback checkpoint is corrupted.");
  }
  requireRevision(value.revision);
  const manifestSeq = BigInt(value.manifest_seq);
  if (manifestSeq > MAX_MANIFEST_SEQ) {
    throw new VaultRollbackError("The trusted vault rollback checkpoint is corrupted.");
  }
  return {
    revision: value.revision,
    manifestSeq,
    manifestDigest: value.manifest_digest,
  };
}

function serializeAnchor(anchor) {
  requireRevision(anchor.revision);
  if (
    typeof anchor.manifestSeq !== "bigint" ||
    anchor.manifestSeq < 0n ||
    anchor.manifestSeq > MAX_MANIFEST_SEQ ||
    !/^[0-9a-f]{64}$/.test(anchor.manifestDigest)
  ) {
    throw new VaultRollbackError("The new vault rollback checkpoint is invalid.");
  }
  return {
    version: ANCHOR_VERSION,
    revision: anchor.revision,
    manifest_seq: anchor.manifestSeq.toString(),
    manifest_digest: anchor.manifestDigest,
  };
}

export function vaultRollbackAnchorKey(server, accountId) {
  if (!server || !accountId) throw new Error("Vault rollback scope is incomplete.");
  return `${ANCHOR_PREFIX}:${encodeURIComponent(server)}:${encodeURIComponent(accountId)}`;
}

/**
 * Move a legacy case-sensitive checkpoint scope to the canonical account id.
 *
 * If both scopes already exist, one must cryptographically dominate the other.
 * Incomparable revision/sequence/digest histories fail closed rather than
 * selecting whichever key happened to be read last.
 */
export async function migrateVaultRollbackAnchorScope(
  area,
  server,
  legacyAccountId,
  canonicalAccountId
) {
  const legacyKey = vaultRollbackAnchorKey(server, legacyAccountId);
  const canonicalKey = vaultRollbackAnchorKey(server, canonicalAccountId);
  if (legacyKey === canonicalKey) return canonicalKey;

  const [firstKey, secondKey] = [legacyKey, canonicalKey].sort();
  return withVaultRollbackLock(firstKey, () =>
    withVaultRollbackLock(secondKey, async () => {
      const legacy = await readVaultRollbackAnchor(area, legacyKey);
      if (!legacy) return canonicalKey;
      const canonical = await readVaultRollbackAnchor(area, canonicalKey);
      let winner = legacy;
      if (canonical) {
        try {
          assertVaultRollbackProgress(legacy, canonical);
        } catch {
          try {
            assertVaultRollbackProgress(canonical, legacy);
            winner = canonical;
          } catch {
            throw new VaultRollbackError(
              "Case-variant vault rollback checkpoints conflict."
            );
          }
        }
      }
      await writeVaultRollbackAnchor(area, canonicalKey, winner);
      try {
        await area.remove(legacyKey);
      } catch {
        throw new VaultRollbackError(
          "The legacy vault rollback checkpoint could not be removed."
        );
      }
      return canonicalKey;
    })
  );
}

export async function readVaultRollbackAnchor(area, key) {
  let values;
  try {
    values = await area.get(key);
  } catch {
    throw new VaultRollbackError("Trusted vault rollback storage is unavailable.");
  }
  const value = values?.[key];
  return value === undefined ? null : parseAnchor(value);
}

async function sha256Hex(value) {
  if (!globalThis.crypto?.subtle) {
    throw new VaultRollbackError("Cryptographic rollback verification is unavailable.");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

export async function createVaultRollbackAnchor(integrity) {
  requireRevision(integrity?.revision);
  if (
    typeof integrity.manifestSeq !== "bigint" ||
    integrity.manifestSeq < 0n ||
    integrity.manifestSeq > MAX_MANIFEST_SEQ ||
    typeof integrity.manifestJson !== "string"
  ) {
    throw new VaultRollbackError("The verified manifest checkpoint is invalid.");
  }
  return {
    revision: integrity.revision,
    manifestSeq: integrity.manifestSeq,
    manifestDigest: await sha256Hex(integrity.manifestJson),
  };
}

export function assertVaultRollbackProgress(candidate, trusted) {
  if (!trusted) return;
  if (candidate.revision < trusted.revision || candidate.manifestSeq < trusted.manifestSeq) {
    throw new VaultRollbackError("A vault rollback was detected.");
  }
  if (
    candidate.revision === trusted.revision &&
    candidate.manifestSeq !== trusted.manifestSeq
  ) {
    throw new VaultRollbackError("The vault revision conflicts with its trusted sequence.");
  }
  if (
    candidate.manifestSeq === trusted.manifestSeq &&
    candidate.manifestDigest !== trusted.manifestDigest
  ) {
    throw new VaultRollbackError("The vault manifest conflicts with its trusted checkpoint.");
  }
}

export async function writeVaultRollbackAnchor(area, key, candidate) {
  const current = await readVaultRollbackAnchor(area, key);
  assertVaultRollbackProgress(candidate, current);
  const serialized = serializeAnchor(candidate);
  try {
    await area.set({ [key]: serialized });
  } catch {
    throw new VaultRollbackError("The trusted vault rollback checkpoint could not be saved.");
  }
  const persisted = await readVaultRollbackAnchor(area, key);
  if (
    !persisted ||
    persisted.revision !== candidate.revision ||
    persisted.manifestSeq !== candidate.manifestSeq ||
    persisted.manifestDigest !== candidate.manifestDigest
  ) {
    throw new VaultRollbackError("The trusted vault rollback checkpoint was not saved exactly.");
  }
}

/** Serialize compare-and-store operations inside the extension service worker. */
export async function withVaultRollbackLock(key, operation) {
  const previous = anchorLocks.get(key) || Promise.resolve();
  const run = previous.catch(() => {}).then(operation);
  const tail = run.then(
    () => undefined,
    () => undefined
  );
  anchorLocks.set(key, tail);
  try {
    return await run;
  } finally {
    if (anchorLocks.get(key) === tail) anchorLocks.delete(key);
  }
}
