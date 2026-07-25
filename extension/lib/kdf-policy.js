// Browser Argon2id policy mirrored from crypto-core's KdfParams.
// Prelogin is unauthenticated, so a sync server must not be allowed to weaken
// the offline-attack cost or force excessive browser work.
export const MIN_MEM_KIB = 19 * 1024;
export const MIN_ITERATIONS = 2;
export const MIN_PARALLELISM = 1;
export const MAX_MEM_KIB = 128 * 1024;
export const MAX_ITERATIONS = 6;
export const MAX_PARALLELISM = 4;

export function assertUnlockKdfPolicy(kdf) {
  if (
    !kdf ||
    typeof kdf !== "object" ||
    !Number.isSafeInteger(kdf.mem_kib) ||
    kdf.mem_kib < MIN_MEM_KIB ||
    kdf.mem_kib > MAX_MEM_KIB ||
    !Number.isSafeInteger(kdf.iterations) ||
    kdf.iterations < MIN_ITERATIONS ||
    kdf.iterations > MAX_ITERATIONS ||
    !Number.isSafeInteger(kdf.parallelism) ||
    kdf.parallelism < MIN_PARALLELISM ||
    kdf.parallelism > MAX_PARALLELISM
  ) {
    throw new Error(
      "The server offered unsafe key-derivation parameters. Unlocking was refused."
    );
  }
}
