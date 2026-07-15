import assert from "node:assert/strict";
import test from "node:test";

import { normalizeServerUrl } from "../lib/server-url.js";

test("allows and canonicalizes loopback HTTP origins", () => {
  assert.deepEqual(normalizeServerUrl("  http://127.0.0.1:7777/  "), {
    url: "http://127.0.0.1:7777",
    permissionPattern: "http://127.0.0.1:7777/*",
    hasBuiltInPermission: true,
  });
  assert.equal(normalizeServerUrl("http://localhost:7777").hasBuiltInPermission, true);
});

test("requires HTTPS for non-loopback origins", () => {
  assert.throws(() => normalizeServerUrl("http://vault.example.com"), /must use HTTPS/);
  assert.deepEqual(normalizeServerUrl("https://vault.example.com/"), {
    url: "https://vault.example.com",
    permissionPattern: "https://vault.example.com/*",
    hasBuiltInPermission: false,
  });
});

test("rejects ambiguous or credential-bearing base URLs", () => {
  for (const value of [
    "ftp://vault.example.com",
    "https://user:pass@vault.example.com",
    "https://vault.example.com/api",
    "https://vault.example.com?target=other",
    "https://vault.example.com/#fragment",
    "not a URL",
  ]) {
    assert.throws(() => normalizeServerUrl(value), undefined, `accepted ${value}`);
  }
});
