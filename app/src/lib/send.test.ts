import { describe, expect, it, vi } from "vitest";
import type { Account } from "./wasm";
import { openMessage, type Contact } from "./send";

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
