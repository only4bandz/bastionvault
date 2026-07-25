import assert from "node:assert/strict";
import test from "node:test";

import {
  PENDING_TTL_MS,
  makePendingSave,
  pendingSaveExpiresAt,
  pendingSaveIsExpired,
} from "../lib/pending-save.js";

test("binds a pending credential to an exact proactive expiry", () => {
  const pending = makePendingSave({ username: "alice", password: "secret" }, 1_000);
  assert.equal(pendingSaveExpiresAt(pending), 1_000 + PENDING_TTL_MS);
  assert.equal(pendingSaveIsExpired(pending, 1_000 + PENDING_TTL_MS), false);
  assert.equal(pendingSaveIsExpired(pending, 1_001 + PENDING_TTL_MS), true);
});

test("fails closed on missing, malformed, or future timestamps", () => {
  assert.equal(pendingSaveIsExpired(null, 1_000), true);
  assert.equal(pendingSaveIsExpired({ stagedAt: "1000" }, 1_000), true);
  assert.equal(pendingSaveIsExpired({ stagedAt: 1_001 }, 1_000), true);
});
