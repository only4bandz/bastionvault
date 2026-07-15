import type { VaultIntegrityState } from "./vault-integrity";

const ANCHOR_VERSION = 1;
const ANCHOR_PREFIX = "bastion:vault-rollback-anchor:v1";
const MAX_MANIFEST_SEQ = (1n << 64n) - 1n;
const RECOVERY_GUIDANCE =
  "Restore the latest server state. To intentionally trust a verified recovery snapshot, clear this site's data first.";

export interface VaultRollbackAnchor {
  revision: number;
  manifestSeq: bigint;
  manifestDigest: string;
}

export interface AnchorStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

interface SerializedAnchor {
  version: number;
  revision: number;
  manifest_seq: string;
  manifest_digest: string;
}

export class VaultRollbackError extends Error {
  constructor(message: string) {
    super(`${message} ${RECOVERY_GUIDANCE}`);
    this.name = "VaultRollbackError";
  }
}

function requireRevision(revision: number): void {
  if (!Number.isSafeInteger(revision) || revision < 0) {
    throw new VaultRollbackError("The trusted vault revision is invalid.");
  }
}

function parseAnchor(raw: string): VaultRollbackAnchor {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new VaultRollbackError("The trusted vault rollback checkpoint is corrupted.");
  }
  if (!parsed || typeof parsed !== "object") {
    throw new VaultRollbackError("The trusted vault rollback checkpoint is corrupted.");
  }
  const value = parsed as Partial<SerializedAnchor>;
  const keys = Object.keys(value).sort();
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

function serializeAnchor(anchor: VaultRollbackAnchor): string {
  requireRevision(anchor.revision);
  if (
    anchor.manifestSeq < 0n ||
    anchor.manifestSeq > MAX_MANIFEST_SEQ ||
    !/^[0-9a-f]{64}$/.test(anchor.manifestDigest)
  ) {
    throw new VaultRollbackError("The new vault rollback checkpoint is invalid.");
  }
  return JSON.stringify({
    version: ANCHOR_VERSION,
    revision: anchor.revision,
    manifest_seq: anchor.manifestSeq.toString(),
    manifest_digest: anchor.manifestDigest,
  } satisfies SerializedAnchor);
}

export function vaultRollbackAnchorKey(apiScope: string, accountId: string): string {
  if (!apiScope || !accountId) throw new Error("Vault rollback scope is incomplete.");
  return `${ANCHOR_PREFIX}:${encodeURIComponent(apiScope)}:${encodeURIComponent(accountId)}`;
}

export function readVaultRollbackAnchor(
  storage: AnchorStorage,
  key: string
): VaultRollbackAnchor | null {
  let raw: string | null;
  try {
    raw = storage.getItem(key);
  } catch {
    throw new VaultRollbackError("Trusted vault rollback storage is unavailable.");
  }
  return raw === null ? null : parseAnchor(raw);
}

async function sha256Hex(value: string): Promise<string> {
  if (!globalThis.crypto?.subtle) {
    throw new VaultRollbackError("Cryptographic rollback verification is unavailable.");
  }
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function createVaultRollbackAnchor(
  state: VaultIntegrityState
): Promise<VaultRollbackAnchor> {
  requireRevision(state.revision);
  if (state.manifestSeq < 0n || state.manifestSeq > MAX_MANIFEST_SEQ) {
    throw new VaultRollbackError("The verified manifest sequence is invalid.");
  }
  return {
    revision: state.revision,
    manifestSeq: state.manifestSeq,
    manifestDigest: await sha256Hex(state.manifestJson),
  };
}

export function assertVaultRollbackProgress(
  candidate: VaultRollbackAnchor,
  trusted: VaultRollbackAnchor | null
): void {
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

export function writeVaultRollbackAnchor(
  storage: AnchorStorage,
  key: string,
  candidate: VaultRollbackAnchor
): void {
  const current = readVaultRollbackAnchor(storage, key);
  assertVaultRollbackProgress(candidate, current);
  const serialized = serializeAnchor(candidate);
  try {
    storage.setItem(key, serialized);
  } catch {
    throw new VaultRollbackError("The trusted vault rollback checkpoint could not be saved.");
  }
  const persisted = readVaultRollbackAnchor(storage, key);
  if (
    !persisted ||
    persisted.revision !== candidate.revision ||
    persisted.manifestSeq !== candidate.manifestSeq ||
    persisted.manifestDigest !== candidate.manifestDigest
  ) {
    throw new VaultRollbackError("The trusted vault rollback checkpoint was not saved exactly.");
  }
}

/** Serialize checkpoint compare-and-store operations across same-origin tabs. */
export async function withVaultRollbackLock<T>(
  key: string,
  operation: () => Promise<T>
): Promise<T> {
  if (typeof navigator === "undefined" || !navigator.locks) {
    throw new VaultRollbackError("Cross-tab rollback protection is unavailable.");
  }
  return navigator.locks.request(`bastion-vault-anchor:${key}`, { mode: "exclusive" }, operation);
}
