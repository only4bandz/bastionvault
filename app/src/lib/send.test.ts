import { afterEach, describe, expect, it, vi } from "vitest";
import type { Account } from "./wasm";
import { api } from "./api";
import {
  openMessage,
  requireContactsPayload,
  sendEnable,
  sendState,
  type Contact,
} from "./send";

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

describe("Send sender identity presentation", () => {
  const unverified: Contact = { ...contact, bastion_id: "BOB", display: "Bob", verified: false };

  function accountReturning(payload: Record<string, unknown>): {
    account: Account;
    pins: () => Record<string, unknown>;
  } {
    const sendOpen = vi.fn(
      (_blob: string, _passphrase: string | undefined, _pins: string) => JSON.stringify(payload)
    );
    return {
      account: { send_open_with_pins: sendOpen } as unknown as Account,
      pins: () => JSON.parse(sendOpen.mock.calls[0][2]) as Record<string, unknown>,
    };
  }

  it("pins every known contact, not only the verified ones", () => {
    const { account, pins } = accountReturning({ sender: { state: "anonymous", id: null } });
    openMessage(account, [contact, unverified], {});
    expect(pins()).toEqual({ ALICE: contact.public, BOB: unverified.public });
  });

  it("never lends a contact's name to a self-asserted sender id", () => {
    // The id matches a contact the user added but never verified: the name
    // must not be borrowed, so the UI falls back to the raw address.
    const { account } = accountReturning({
      plaintext: "hi",
      sender: { state: "unverified", id: "BOB" },
    });
    const opened = openMessage(account, [contact, unverified], {});
    expect(opened.display).toBeNull();
  });

  it("separates a checked signature from an out-of-band verification", () => {
    const { account } = accountReturning({
      plaintext: "hi",
      sender: { state: "verified", id: "BOB" },
    });
    const opened = openMessage(account, [contact, unverified], {});
    // The signature checks out against the pin, but the pin came from the
    // server — that is weaker than a compared safety number and says so.
    expect(opened.signedOnly).toBe(true);
    expect(opened.display).toBeNull();

    const verifiedOpen = accountReturning({
      plaintext: "hi",
      sender: { state: "verified", id: "ALICE" },
    });
    const fully = openMessage(verifiedOpen.account, [contact, unverified], {});
    expect(fully.signedOnly).toBe(false);
    expect(fully.display).toBe("Alice");
  });
});

describe("Send passphrase prompting", () => {
  const protectedBlob = { pw: { salt: "AA", mem_kib: 19456, iterations: 2, parallelism: 1 } };

  it("prompts only when the blob actually carries a passphrase block", () => {
    const account = { send_open_with_pins: vi.fn() } as unknown as Account;
    expect(openMessage(account, [contact], protectedBlob).needsPass).toBe(true);
    // WASM is not even consulted: the answer is in the blob.
    expect(account.send_open_with_pins).not.toHaveBeenCalled();
  });

  it("never turns an undecryptable message into a passphrase prompt", () => {
    // A junk blob the server dropped into the inbox. Prompting here would
    // coax the user into typing an out-of-band passphrase into it.
    const account = {
      send_open_with_pins: () => {
        throw new Error("aead");
      },
    } as unknown as Account;
    const opened = openMessage(account, [contact], { body: "garbage" });

    expect(opened.needsPass).toBeUndefined();
    expect(opened.error).toMatch(/tampered/i);
  });

  it("reports a wrong passphrase distinctly from an untrusted message", () => {
    const account = {
      send_open_with_pins: () => {
        throw new Error("aead");
      },
    } as unknown as Account;
    const opened = openMessage(account, [contact], protectedBlob, "wrong");
    expect(opened.error).toMatch(/wrong passphrase/i);
  });
});

describe("Send identity ownership", () => {
  const mine = { enc_pub: Array(32).fill(1), sig_pub: Array(32).fill(2), key_version: 1 };
  const attacker = { enc_pub: Array(32).fill(9), sig_pub: Array(32).fill(8), key_version: 1 };

  function accountWithIdentity(): Account {
    return {
      has_send_identity: true,
      send_identity_public: () => JSON.stringify(mine),
    } as unknown as Account;
  }

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows no address when the server reports a different identity", async () => {
    // A malicious server answers whoami with an attacker's address and key.
    // Publishing it as "your Bastion address" would route every future note
    // to the attacker while the victim's own inbox stayed silent.
    vi.spyOn(api, "whoami").mockResolvedValue({ bastion_id: "ATTACKER", public: attacker });

    const state = await sendState(accountWithIdentity(), "token");
    expect(state.enabled).toBe(true);
    expect(state.bastionId).toBeNull();
  });

  it("accepts the address when the reported identity is ours", async () => {
    vi.spyOn(api, "whoami").mockResolvedValue({ bastion_id: "MINE", public: mine });

    const state = await sendState(accountWithIdentity(), "token");
    expect(state.bastionId).toBe("MINE");
  });

  it("refuses to enable against a foreign published identity", async () => {
    vi.spyOn(api, "whoami").mockResolvedValue({ bastion_id: "ATTACKER", public: attacker });

    await expect(
      sendEnable(accountWithIdentity(), "token", async () => undefined)
    ).rejects.toThrow(/different Send key/i);
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
