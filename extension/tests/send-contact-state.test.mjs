import assert from "node:assert/strict";
import test from "node:test";

import { requireContactsPayload } from "../lib/send-contact-state.js";

const valid = {
  bastion_id: "A".repeat(26),
  public: { enc_pub: Array(32).fill(1), sig_pub: Array(32).fill(2), key_version: 1 },
  pinFp: "ab".repeat(32),
  display: "Alice",
  verified: true,
  verified_at: 1,
  safety_number: "1".repeat(60),
};

test("accepts canonical verified and unverified contact state", () => {
  assert.deepEqual(requireContactsPayload([valid]), [valid]);
  assert.equal(
    requireContactsPayload([{ ...valid, verified: false, verified_at: null }]).length,
    1
  );
  assert.equal(
    requireContactsPayload([
      {
        ...valid,
        lock_enabled: true,
        lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
        lock_kdf: { mem_kib: 128 * 1024, iterations: 3, parallelism: 1 },
      },
    ]).length,
    1
  );
});

test("rejects malformed, ambiguous, and duplicate contact state", () => {
  for (const value of [
    [{ ...valid, extra: true }],
    [{ ...valid, bastion_id: "ALICE" }],
    [{ ...valid, public: { ...valid.public, sig_pub: [1] } }],
    [{ ...valid, pinFp: "fingerprint" }],
    [{ ...valid, safety_number: "123" }],
    [{ ...valid, verified: false }],
    [valid, { ...valid, display: "Duplicate" }],
    [{ ...valid, display: "é".repeat(101) }],
    Array(1_001).fill(valid),
    [{ ...valid, lock_enabled: true }],
    [{
      ...valid,
      lock_enabled: true,
      lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
      lock_kdf: { mem_kib: 8, iterations: 1, parallelism: 1 },
    }],
    [{
      ...valid,
      lock_enabled: true,
      lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
      lock_kdf: { mem_kib: 128 * 1024 + 1, iterations: 3, parallelism: 1 },
    }],
  ]) {
    assert.throws(() => requireContactsPayload(value), /invalid contacts payload/);
  }
});
