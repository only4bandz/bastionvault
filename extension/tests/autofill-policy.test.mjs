import assert from "node:assert/strict";
import test from "node:test";

import { autofillPolicyError } from "../lib/autofill-policy.js";

const login = { type: "login", title: "Example", url: "https://accounts.example.com/login" };

test("allows the selected tab on the saved site", () => {
  assert.equal(autofillPolicyError(login, { id: 7, url: "https://www.example.com/sign-in" }, 7), null);
});

test("rejects a different active tab", () => {
  assert.match(autofillPolicyError(login, { id: 8, url: "https://example.com" }, 7), /tab changed/i);
});

test("rejects same-tab navigation to another site", () => {
  assert.match(autofillPolicyError(login, { id: 7, url: "https://example.net/login" }, 7), /not saved/i);
});

test("rejects unrelated and non-login items", () => {
  assert.match(
    autofillPolicyError({ ...login, url: "https://bank.example" }, { id: 7, url: "https://shop.example" }, 7),
    /not saved/i
  );
  assert.match(autofillPolicyError({ type: "card" }, { id: 7, url: "https://example.com" }, 7), /only login/i);
});
