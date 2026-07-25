import assert from "node:assert/strict";
import test from "node:test";

import {
  assertUnlockKdfPolicy,
  MAX_ITERATIONS,
  MAX_MEM_KIB,
  MAX_PARALLELISM,
  MIN_ITERATIONS,
  MIN_MEM_KIB,
  MIN_PARALLELISM,
} from "../lib/kdf-policy.js";

const defaults = { mem_kib: 64 * 1024, iterations: 3, parallelism: 4 };

test("accepts browser KDF defaults and exact policy boundaries", () => {
  assert.doesNotThrow(() => assertUnlockKdfPolicy(defaults));
  assert.doesNotThrow(() =>
    assertUnlockKdfPolicy({
      mem_kib: MIN_MEM_KIB,
      iterations: MIN_ITERATIONS,
      parallelism: MIN_PARALLELISM,
    })
  );
  assert.doesNotThrow(() =>
    assertUnlockKdfPolicy({
      mem_kib: MAX_MEM_KIB,
      iterations: MAX_ITERATIONS,
      parallelism: MAX_PARALLELISM,
    })
  );
});

test("rejects server-controlled KDF weakening and resource exhaustion", () => {
  for (const kdf of [
    { ...defaults, mem_kib: MIN_MEM_KIB - 1 },
    { ...defaults, iterations: MIN_ITERATIONS - 1 },
    { ...defaults, parallelism: MIN_PARALLELISM - 1 },
    { ...defaults, mem_kib: MAX_MEM_KIB + 1 },
    { ...defaults, iterations: MAX_ITERATIONS + 1 },
    { ...defaults, parallelism: MAX_PARALLELISM + 1 },
    { ...defaults, mem_kib: 1.5 },
    null,
  ]) {
    assert.throws(() => assertUnlockKdfPolicy(kdf), /unsafe key-derivation/);
  }
});
