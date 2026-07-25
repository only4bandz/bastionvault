import { describe, expect, it } from "vitest";
import {
  assertUnlockKdfPolicy,
  MAX_ITERATIONS,
  MAX_MEM_KIB,
  MAX_PARALLELISM,
  MIN_ITERATIONS,
  MIN_MEM_KIB,
  MIN_PARALLELISM,
} from "./kdf-policy";

const GOOD = { mem_kib: 64 * 1024, iterations: 3, parallelism: 4 };

describe("assertUnlockKdfPolicy", () => {
  it("accepts the registration defaults", () => {
    expect(() => assertUnlockKdfPolicy(GOOD)).not.toThrow();
  });

  it("accepts parameters exactly at the floor", () => {
    expect(() =>
      assertUnlockKdfPolicy({
        mem_kib: MIN_MEM_KIB,
        iterations: MIN_ITERATIONS,
        parallelism: MIN_PARALLELISM,
      })
    ).not.toThrow();
  });

  it("accepts parameters exactly at the browser ceiling", () => {
    expect(() =>
      assertUnlockKdfPolicy({
        mem_kib: MAX_MEM_KIB,
        iterations: MAX_ITERATIONS,
        parallelism: MAX_PARALLELISM,
      })
    ).not.toThrow();
  });

  it.each([
    ["memory below floor", { ...GOOD, mem_kib: MIN_MEM_KIB - 1 }],
    ["trivial memory", { ...GOOD, mem_kib: 8 }],
    ["iterations below floor", { ...GOOD, iterations: MIN_ITERATIONS - 1 }],
    ["zero parallelism", { ...GOOD, parallelism: 0 }],
    ["memory above browser ceiling", { ...GOOD, mem_kib: MAX_MEM_KIB + 1 }],
    ["iterations above browser ceiling", { ...GOOD, iterations: MAX_ITERATIONS + 1 }],
    ["parallelism above browser ceiling", { ...GOOD, parallelism: MAX_PARALLELISM + 1 }],
    ["NaN memory", { ...GOOD, mem_kib: Number.NaN }],
    ["infinite iterations treated as malformed", { ...GOOD, iterations: Number.POSITIVE_INFINITY }],
  ])("rejects %s", (_name, kdf) => {
    expect(() => assertUnlockKdfPolicy(kdf)).toThrow(/unsafe key-derivation/);
  });
});
