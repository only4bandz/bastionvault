import assert from "node:assert/strict";
import test from "node:test";

import {
  SESSION_ABSOLUTE_MS,
  boundedSessionExpiry,
  newAbsoluteSessionDeadline,
  storedSessionDeadlines,
} from "../lib/session-deadline.js";

test("never slides an unlocked session beyond its original absolute deadline", () => {
  const unlockedAt = 1_000_000;
  const absolute = newAbsoluteSessionDeadline(unlockedAt);
  assert.equal(absolute, unlockedAt + SESSION_ABSOLUTE_MS);
  assert.equal(
    boundedSessionExpiry(absolute - 60_000, 60, absolute),
    absolute
  );
  assert.equal(
    boundedSessionExpiry(unlockedAt, 10, absolute),
    unlockedAt + 10 * 60_000
  );
});

test("uses a legacy record's existing expiry as a non-extending ceiling", () => {
  const legacy = { expiresAt: 2_000_000 };
  assert.deepEqual(storedSessionDeadlines(legacy, 1_000_000), {
    expiresAt: 2_000_000,
    absoluteExpiresAt: 2_000_000,
  });
});

test("rejects expired and malformed persisted session deadlines", () => {
  for (const stored of [
    null,
    {},
    { expiresAt: "later" },
    { expiresAt: 100, absoluteExpiresAt: 200 },
    { expiresAt: 200, absoluteExpiresAt: 100 },
  ]) {
    assert.equal(storedSessionDeadlines(stored, 150), null);
  }
  assert.equal(boundedSessionExpiry(0, 0, 100), null);
});
