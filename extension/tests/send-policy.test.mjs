import assert from "node:assert/strict";
import test from "node:test";

import { SIGNING_UNAVAILABLE, senderIdForMode } from "../lib/send-policy.js";

test("anonymous mode never resolves or attaches a sender identity", async () => {
  let lookedUp = false;
  const id = await senderIdForMode({
    signed: false,
    cachedId: "CACHED",
    lookup: async () => {
      lookedUp = true;
      return "LOOKED-UP";
    },
  });
  assert.equal(id, null);
  assert.equal(lookedUp, false);
});

test("signed mode uses a confirmed cached or fetched identity", async () => {
  assert.equal(
    await senderIdForMode({ signed: true, cachedId: "CACHED", lookup: async () => "OTHER" }),
    "CACHED"
  );
  assert.equal(
    await senderIdForMode({ signed: true, cachedId: null, lookup: async () => "FETCHED" }),
    "FETCHED"
  );
});

test("signed mode fails instead of downgrading when identity lookup fails", async () => {
  await assert.rejects(
    senderIdForMode({
      signed: true,
      cachedId: null,
      lookup: async () => {
        throw new Error("offline");
      },
    }),
    new RegExp(SIGNING_UNAVAILABLE.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
  );
  await assert.rejects(
    senderIdForMode({ signed: true, cachedId: null, lookup: async () => null }),
    /Nothing was sent/
  );
});
