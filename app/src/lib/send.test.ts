import { describe, expect, it, vi } from "vitest";
import type { Account } from "./wasm";
import { openMessage, requireContactsPayload, type Contact } from "./send";

const contact: Contact = {
  bastion_id: "ALICE",
  public: { enc_pub: Array(32).fill(1), sig_pub: Array(32).fill(2), key_version: 1 },
  pinFp: "fingerprint",
  display: "Alice",
  verified: true,
  verified_at: 1,
  safety_number: "123",
};

describe("Send pinned plaintext release", () => {
  it("returns no plaintext when WASM reports a pinned-key failure", () => {
    const sendOpen = vi.fn((_blob: string, _passphrase: string | undefined, _pins: string) =>
      JSON.stringify({
        sender: { state: "unverified", id: "ALICE" },
        keyChanged: true,
      })
    );
    const account = { send_open_with_pins: sendOpen } as unknown as Account;
    const opened = openMessage(account, [contact], { encrypted: true });

    expect(opened.keyChanged).toBe(true);
    expect(opened.plaintext).toBeUndefined();
    expect(opened.display).toBe("Alice");
    expect(JSON.parse(sendOpen.mock.calls[0][2])).toEqual({ ALICE: contact.public });
  });

  it("returns only the plaintext approved by the pinned WASM open", () => {
    const account = {
      send_open_with_pins: () =>
        JSON.stringify({
          plaintext: "verified plaintext",
          sender: { state: "verified", id: "ALICE" },
        }),
    } as unknown as Account;
    expect(openMessage(account, [contact], {}).plaintext).toBe("verified plaintext");
  });
});

describe("encrypted Send contact state", () => {
  const bastionId = "A".repeat(26);
  const valid = {
    bastion_id: bastionId,
    public: { enc_pub: Array(32).fill(1), sig_pub: Array(32).fill(2), key_version: 1 },
    pinFp: "ab".repeat(32),
    display: "Alice",
    verified: true,
    verified_at: 1,
    safety_number: "1".repeat(60),
  };

  it("accepts only canonical, unique contact records", () => {
    expect(requireContactsPayload([valid])).toEqual([valid]);
    expect(requireContactsPayload([{ ...valid, verified: false, verified_at: null }]))
      .toHaveLength(1);
    expect(
      requireContactsPayload([
        {
          ...valid,
          lock_enabled: true,
          lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
          lock_kdf: { mem_kib: 128 * 1024, iterations: 3, parallelism: 1 },
        },
      ])
    ).toHaveLength(1);
  });

  it.each([
    ["unknown fields", [{ ...valid, extra: true }]],
    ["invalid address", [{ ...valid, bastion_id: "ALICE" }]],
    ["invalid public identity", [{ ...valid, public: { ...valid.public, enc_pub: [1] } }]],
    ["invalid pin", [{ ...valid, pinFp: "fingerprint" }]],
    ["invalid safety number", [{ ...valid, safety_number: "123" }]],
    ["unverified timestamp", [{ ...valid, verified: false }]],
    ["duplicate address", [valid, { ...valid, display: "Duplicate" }]],
    ["partial lock metadata", [{ ...valid, lock_enabled: true }]],
    [
      "weak lock KDF",
      [{
        ...valid,
        lock_enabled: true,
        lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
        lock_kdf: { mem_kib: 8, iterations: 1, parallelism: 1 },
      }],
    ],
    [
      "oversized lock KDF",
      [{
        ...valid,
        lock_enabled: true,
        lock_salt: "AAECAwQFBgcICQoLDA0ODw==",
        lock_kdf: { mem_kib: 128 * 1024 + 1, iterations: 3, parallelism: 1 },
      }],
    ],
  ])("rejects %s", (_name, value) => {
    expect(() => requireContactsPayload(value)).toThrow("invalid contacts payload");
  });

  it("bounds contact count and display size", () => {
    expect(() => requireContactsPayload(Array(1_001).fill(valid))).toThrow(
      "invalid contacts payload"
    );
    expect(() =>
      requireContactsPayload([{ ...valid, display: "é".repeat(101) }])
    ).toThrow("invalid contacts payload");
  });
});
