import assert from "node:assert/strict";
import test from "node:test";

import { SECRET_FIELDS, redactItem } from "../lib/item-redaction.js";

const login = {
  id: "abc",
  type: "login",
  title: "Example",
  username: "alice@example.com",
  password: "correct horse battery",
  url: "https://example.com",
  notes: "recovery: 1234",
};

const card = {
  id: "def",
  type: "card",
  title: "Bank",
  username: "Alice Doe",
  cardNumber: "4111111111111111",
  cardExp: "12/28",
  cardCvv: "737",
};

test("no secret field survives redaction", () => {
  for (const item of [login, card]) {
    const redacted = redactItem(item);
    for (const field of SECRET_FIELDS) {
      assert.equal(Object.hasOwn(redacted, field), false, `${field} was still present`);
    }
    // Nothing anywhere in the payload still spells a secret out.
    const serialized = JSON.stringify(redacted);
    for (const field of SECRET_FIELDS) {
      if (item[field]) assert.equal(serialized.includes(item[field]), false, `${field} leaked`);
    }
  }
});

test("the detail view keeps everything it needs to render", () => {
  const redacted = redactItem(login);
  assert.equal(redacted.username, login.username);
  assert.equal(redacted.url, login.url);
  assert.equal(redacted.notes, login.notes);
  // Mask width without the value, and health computed before redaction.
  assert.equal(redacted.secretLengths.password, login.password.length);
  assert.equal(redacted.passwordHealth.label, "Fair password");

  // A genuinely strong password still reports as strong, from the same
  // pre-redaction computation.
  const strong = redactItem({ ...login, password: "Tr0ub4dor&3xample!" });
  assert.equal(strong.passwordHealth.ok, true);
  assert.equal(strong.passwordHealth.label, "Strong password");

  const redactedCard = redactItem(card);
  assert.equal(redactedCard.cardExp, card.cardExp);
  assert.equal(redactedCard.secretLengths.cardNumber, 16);
  assert.equal(redactedCard.secretLengths.cardCvv, 3);
});

test("absent secrets produce no mask entry", () => {
  const redacted = redactItem({ id: "x", type: "login", title: "No password" });
  assert.deepEqual(redacted.secretLengths, {});
  assert.equal(redacted.passwordHealth.label, "No password");
  assert.equal(redacted.passwordHealth.ok, false);
});

test("a weak password is still reported as weak", () => {
  const redacted = redactItem({ ...login, password: "abc" });
  assert.equal(redacted.secretLengths.password, 3);
  assert.equal(redacted.passwordHealth.ok, false);
});
