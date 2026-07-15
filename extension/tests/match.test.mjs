import assert from "node:assert/strict";
import test from "node:test";

import { matchesSite } from "../lib/match.js";

test("allows subdomains of the same registrable site", () => {
  assert.equal(matchesSite("https://accounts.example.co.uk/login", "shop.example.co.uk"), true);
  assert.equal(matchesSite("https://example.com", "login.example.com"), true);
});

test("keeps different tenants on private suffixes isolated", () => {
  assert.equal(matchesSite("https://alice.github.io", "bob.github.io"), false);
  assert.equal(matchesSite("https://one.vercel.app", "two.vercel.app"), false);
});

test("does not release credentials across formerly equivalent brands", () => {
  for (const [saved, page] of [
    ["live.com", "microsoftonline.com"],
    ["google.com", "youtube.com"],
    ["apple.com", "icloud.com"],
    ["amazon.com", "amazon.ca"],
    ["facebook.com", "instagram.com"],
  ]) {
    assert.equal(matchesSite(saved, page), false, `${saved} unexpectedly matched ${page}`);
  }
});

test("rejects values without a valid domain", () => {
  assert.equal(matchesSite("Personal account", "example.com"), false);
  assert.equal(matchesSite("example.com", "localhost"), false);
});
