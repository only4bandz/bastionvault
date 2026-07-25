import { describe, expect, it } from "vitest";
import { isLockedSendRecord } from "./send-locked-state";

const localId = "AAECAwQFBgcICQoLDA0ODw==";
const valid = {
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

describe("locked Send vault records", () => {
  it("accepts a canonical record bound to its storage id", () => {
    expect(isLockedSendRecord(valid, storageId)).toBe(true);
  });

  it.each([
    ["storage substitution", valid, "bastion:send-locked:AAAAAAAAAAAAAAAAAAAAAA=="],
    ["unknown field", { ...valid, extra: true }, storageId],
    ["invalid contact", { ...valid, contact_id: "ALICE" }, storageId],
    ["invalid message id", { ...valid, message_id: "message" }, storageId],
    ["invalid commitment", { ...valid, lock_commit: "short" }, storageId],
    ["negative timestamp", { ...valid, created_at: -1 }, storageId],
    ["invalid body nonce", { ...valid, body: { ...valid.body, nonce: "short" } }, storageId],
    ["empty ciphertext", { ...valid, body: { ...valid.body, ct: "" } }, storageId],
  ])("rejects %s", (_name, value, id) => {
    expect(isLockedSendRecord(value, id)).toBe(false);
  });
});
