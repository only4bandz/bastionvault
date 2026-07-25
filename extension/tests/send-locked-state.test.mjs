import assert from "node:assert/strict";
import test from "node:test";

import {
  isLockedSendRecord,
  requireLockedRecordContacts,
} from "../lib/send-locked-state.js";

const localId = "AAECAwQFBgcICQoLDA0ODw==";
const record = {
  v: 1,
  local_id: localId,
  contact_id: "A".repeat(26),
  message_id: "EBESExQVFhcYGRobHB0eHw==",
  lock_commit: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  body: {
    v: 1,
    nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",
    ct: "AAECAwQFBgcICQoLDA0ODw==",
  },
  created_at: 1,
};
const storageId = `bastion:send-locked:${localId}`;

test("accepts a canonical locked record bound to its vault id", () => {
  assert.equal(isLockedSendRecord(record, storageId), true);
});

test("rejects malformed and substituted locked records", () => {
  for (const [value, id] of [
    [record, "bastion:send-locked:AAAAAAAAAAAAAAAAAAAAAA=="],
    [{ ...record, extra: true }, storageId],
    [{ ...record, contact_id: "ALICE" }, storageId],
    [{ ...record, message_id: "message" }, storageId],
    [{ ...record, lock_commit: "short" }, storageId],
    [{ ...record, created_at: -1 }, storageId],
    [{ ...record, body: { ...record.body, nonce: "short" } }, storageId],
    [{ ...record, body: { ...record.body, ct: "" } }, storageId],
  ]) {
    assert.equal(isLockedSendRecord(value, id), false);
  }
});

test("requires one active lock contact per unique stored message", () => {
  const contacts = [{ bastion_id: record.contact_id, lock_enabled: true }];
  assert.deepEqual(requireLockedRecordContacts([record], contacts), [record]);
  assert.throws(() => requireLockedRecordContacts([record], []), /invalid locked Send state/);
  assert.throws(
    () => requireLockedRecordContacts([record, { ...record, local_id: "other" }], contacts),
    /invalid locked Send state/
  );
});
