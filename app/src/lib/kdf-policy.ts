// Client-side KDF policy floor — mirrors crypto-core's KdfParams minimums
// (crates/crypto-core/src/kdf.rs). The WASM layer only enforces an anti-DoS
// ceiling on unlock, so the floor must be checked HERE, before any key
// derivation runs with server-supplied parameters.
import type { Registration } from "./api";

export type KdfParams = Registration["kdf"];

/** OWASP-aligned Argon2id floor, identical to crypto-core's policy. */
export const MIN_MEM_KIB = 19 * 1024;
export const MIN_ITERATIONS = 2;
export const MIN_PARALLELISM = 1;

/**
 * Refuse to derive keys under below-floor parameters.
 *
 * Threat: prelogin parameters come from the server unauthenticated. A
 * compromised or malicious server can hand out trivial Argon2id costs
 * (e.g. 8 KiB / 1 iteration); the client would then derive and send an
 * auth secret that is cheap to brute-force offline into the master
 * password. Every vault this app has ever created uses at least the
 * default 64 MiB / 3 iterations, so no legitimate account can be locked
 * out by enforcing the floor.
 */
export function assertUnlockKdfPolicy(kdf: KdfParams): void {
  if (
    !Number.isFinite(kdf.mem_kib) ||
    !Number.isFinite(kdf.iterations) ||
    !Number.isFinite(kdf.parallelism) ||
    kdf.mem_kib < MIN_MEM_KIB ||
    kdf.iterations < MIN_ITERATIONS ||
    kdf.parallelism < MIN_PARALLELISM
  ) {
    throw new Error(
      "The server offered dangerously weak key-derivation parameters. " +
        "Unlocking was refused to protect your master password — contact the server operator."
    );
  }
}
