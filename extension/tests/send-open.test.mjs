import assert from "node:assert/strict";
import test from "node:test";

import { openMessage } from "../lib/send-open.js";

const contact = {
  bastion_id: "ALICE",
  public: { enc_pub: Array(32).fill(1), sig_pub: Array(32).fill(2), key_version: 1 },
  display: "Alice",
  verified: true,
};

test("withholds plaintext when WASM reports a pinned-key failure", () => {
  let pins;
  const account = {
    send_open_with_pins(_blob, _passphrase, pinnedJson) {
      pins = JSON.parse(pinnedJson);
      return JSON.stringify({
        sender: { state: "unverified", id: "ALICE" },
        keyChanged: true,
      });
    },
  };
  const opened = openMessage(account, [contact], { encrypted: true });
  assert.equal(opened.keyChanged, true);
  assert.equal(opened.plaintext, undefined);
  assert.equal(opened.display, "Alice");
  assert.deepEqual(pins, { ALICE: contact.public });
});

test("returns plaintext only after the pinned WASM open approves it", () => {
  const account = {
    send_open_with_pins() {
      return JSON.stringify({
        plaintext: "verified plaintext",
        sender: { state: "verified", id: "ALICE" },
      });
    },
  };
  assert.equal(openMessage(account, [contact], {}).plaintext, "verified plaintext");
});
