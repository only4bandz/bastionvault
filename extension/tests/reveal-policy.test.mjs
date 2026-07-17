import assert from "node:assert/strict";
import test from "node:test";

import { isRevealableField, revealFieldValue } from "../lib/reveal-policy.js";

const item = { id: "i1", type: "login", title: "Example", password: "hunter2" };

test("allows the popup's secret fields", () => {
  for (const field of ["password", "cardNumber", "cardCvv", "cardExp", "notes", "username"]) {
    assert.equal(isRevealableField(field), true, field);
  }
  assert.equal(revealFieldValue(item, "password"), "hunter2");
});

test("rejects prototype-chain and internal names", () => {
  for (const field of ["__proto__", "constructor", "prototype", "id", "title", "type", "updatedAt"]) {
    assert.equal(isRevealableField(field), false, field);
    assert.throws(() => revealFieldValue(item, field), /not revealable/i);
  }
  assert.equal(isRevealableField(undefined), false);
  assert.equal(isRevealableField(42), false);
});

test("reads own properties only, defaulting to empty", () => {
  assert.equal(revealFieldValue(item, "notes"), "");
  assert.equal(revealFieldValue(Object.create({ password: "inherited" }), "password"), "");
  assert.equal(revealFieldValue(null, "password"), "");
});
