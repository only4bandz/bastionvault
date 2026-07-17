import assert from "node:assert/strict";
import test from "node:test";

import { IDLE_DETECTION_SECONDS, shouldLockOnIdleState } from "../lib/idle-lock.js";

test("locks when the OS session locks", () => {
  assert.equal(shouldLockOnIdleState("locked"), true);
});

test("does not lock on mere inactivity or return to activity", () => {
  assert.equal(shouldLockOnIdleState("idle"), false);
  assert.equal(shouldLockOnIdleState("active"), false);
});

test("ignores unknown states (future-proof, fails closed to no-op)", () => {
  assert.equal(shouldLockOnIdleState(undefined), false);
  assert.equal(shouldLockOnIdleState("suspended"), false);
});

test("detection interval respects the chrome.idle API minimum", () => {
  assert.ok(IDLE_DETECTION_SECONDS >= 15);
});
