import assert from "node:assert/strict";
import test from "node:test";

import {
  autofillPolicyError,
  credentialPageError,
  frameAutofillError,
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

test("frame guard: same-page and same-site frames are allowed", () => {
  assert.equal(
    frameAutofillError("https://bank.com/login", "https://bank.com/home"),
    null
  );
  assert.equal(
    frameAutofillError("https://auth.bank.com/login", "https://www.bank.com/home"),
    null
  );
});

test("frame guard: cross-site iframes are rejected", () => {
  assert.match(
    frameAutofillError("https://bank.com/login", "https://evil.example/lure"),
    /third-party frames/i
  );
  // PaaS shared suffixes are distinct registrable sites.
  assert.match(
    frameAutofillError("https://a.github.io/x", "https://b.github.io/y"),
    /third-party frames/i
  );
});

test("frame guard: fails closed when the top URL is missing or invalid", () => {
  assert.ok(frameAutofillError("https://bank.com/login", undefined));
  assert.ok(frameAutofillError("https://bank.com/login", "not a url"));
  assert.ok(frameAutofillError(undefined, "https://bank.com/"));
});

test("save pipeline enforces host, HTTPS, and same-site frame rules", async () => {
  const { savePipelineError } = await import("../lib/autofill-policy.js");
  // A same-site HTTPS frame may stage/commit.
  assert.equal(savePipelineError("example.com", null, null), null);
  // No sender host (extension page or unparseable sender) is refused.
  assert.match(savePipelineError(null, null, null), /open a website/i);
  // Insecure-HTTP and third-party-frame errors pass through untouched.
  assert.equal(savePipelineError("example.com", "insecure", null), "insecure");
  assert.equal(savePipelineError("example.com", null, "third-party frame"), "third-party frame");
  // The credential-page rule outranks the frame rule, mirroring CREDS.
  assert.equal(savePipelineError("example.com", "insecure", "frame"), "insecure");
});

test("only a same-site frame may clear a staged pending save", async () => {
  const { contentMayClearPending } = await import("../lib/autofill-policy.js");
  const pending = { host: "example.com", url: "https://example.com/login" };
  assert.equal(contentMayClearPending(pending, "example.com", null), true);
  assert.equal(contentMayClearPending(pending, "www.example.com", null), true);
  // Another site, a third-party frame, or no staged save at all: refused.
  assert.equal(contentMayClearPending(pending, "evil.example.net", null), false);
  assert.equal(contentMayClearPending(pending, "example.com", "third-party frame"), false);
  assert.equal(contentMayClearPending(null, "example.com", null), false);
  assert.equal(contentMayClearPending(pending, null, null), false);
});
