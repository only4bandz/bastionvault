import assert from "node:assert/strict";
import test from "node:test";

import {
  autofillPolicyError,
  credentialPageError,
  validatedAutofillTarget,
} from "../lib/autofill-policy.js";

const login = { type: "login", title: "Example", url: "https://accounts.example.com/login" };

test("allows the selected tab on the saved site", () => {
  assert.equal(autofillPolicyError(login, { id: 7, url: "https://www.example.com/sign-in" }, 7), null);
});

test("rejects credential release to remote HTTP pages", () => {
  assert.match(credentialPageError("http://example.com/login"), /insecure HTTP/i);
  assert.match(autofillPolicyError(login, { id: 7, url: "http://example.com/login" }, 7), /insecure HTTP/i);
});

test("allows explicit HTTP loopback development origins", () => {
  for (const url of ["http://localhost:5173", "http://127.0.0.1:8080", "http://[::1]:3000"]) {
    assert.equal(credentialPageError(url), null);
  }
});

test("rejects non-web and malformed credential destinations", () => {
  for (const url of ["file:///tmp/login.html", "chrome://settings", "not a URL", undefined]) {
    assert.match(credentialPageError(url), /open a website/i);
  }
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

test("binds credential injection to the exact validated top-level document", () => {
  const target = validatedAutofillTarget(login, { id: 7 }, 7, [
    { frameId: 0, documentId: "document-uuid", result: "https://www.example.com/sign-in" },
  ]);

  assert.deepEqual(target, { tabId: 7, documentIds: ["document-uuid"] });
  assert.equal("frameIds" in target, false);
});

test("rejects a probe that navigated to an unrelated or insecure document", () => {
  assert.throws(
    () =>
      validatedAutofillTarget(login, { id: 7 }, 7, [
        { frameId: 0, documentId: "new-document", result: "https://attacker.example.net/login" },
      ]),
    /not saved/i
  );
  assert.throws(
    () =>
      validatedAutofillTarget(login, { id: 7 }, 7, [
        { frameId: 0, documentId: "new-document", result: "http://example.com/login" },
      ]),
    /insecure HTTP/i
  );
});

test("fails closed when Chrome cannot identify one top-level document", () => {
  for (const results of [
    [],
    [{ frameId: 0, result: "https://example.com" }],
    [{ frameId: 1, documentId: "child", result: "https://example.com" }],
    [
      { frameId: 0, documentId: "one", result: "https://example.com" },
      { frameId: 1, documentId: "two", result: "https://example.com" },
    ],
  ]) {
    assert.throws(() => validatedAutofillTarget(login, { id: 7 }, 7, results), /could not be verified/i);
  }
});
