import { describe, expect, it } from "vitest";
import {
  AUTO_LOCK_MS,
  HIDDEN_GRACE_MS,
  createLockSchedule,
} from "./auto-lock";

const T0 = 1_700_000_000_000;

describe("auto-lock schedule", () => {
  it("locks once the idle deadline passes", () => {
    const schedule = createLockSchedule(T0);
    expect(schedule.expired(T0 + AUTO_LOCK_MS - 1)).toBe(false);
    expect(schedule.expired(T0 + AUTO_LOCK_MS)).toBe(true);
  });

  it("only user activity postpones the idle deadline", () => {
    const schedule = createLockSchedule(T0);
    schedule.activity(T0 + 5 * 60_000);
    expect(schedule.expired(T0 + AUTO_LOCK_MS)).toBe(false);
    expect(schedule.expired(T0 + 5 * 60_000 + AUTO_LOCK_MS)).toBe(true);
  });

  it("survives being re-created only when the caller re-creates it", () => {
    // The regression this guards: the effect owning the deadline re-ran on
    // every session rotation (same 10-minute period as the idle deadline),
    // so the timeout was rebuilt from zero and the vault never locked. The
    // schedule now owns an absolute deadline, so an idle session reaches it
    // no matter how often the surrounding effect's dependencies change.
    const schedule = createLockSchedule(T0);
    for (let elapsed = 0; elapsed < AUTO_LOCK_MS; elapsed += 60_000) {
      // Simulated rotations: no user activity, so nothing may move.
      expect(schedule.expired(T0 + elapsed)).toBe(false);
    }
    expect(schedule.expired(T0 + AUTO_LOCK_MS)).toBe(true);
  });

  it("locks on the first tick after a sleep that skipped the deadline", () => {
    const schedule = createLockSchedule(T0);
    // The machine suspended and woke an hour later: no timer fired, but the
    // wall clock is past the deadline.
    expect(schedule.expired(T0 + 60 * 60_000)).toBe(true);
  });

  it("arms the hidden grace deadline once and clears it on return", () => {
    const schedule = createLockSchedule(T0);
    schedule.visibility(true, T0);
    expect(schedule.expired(T0 + HIDDEN_GRACE_MS - 1)).toBe(false);

    // A repeated hidden event must not extend a countdown already running.
    schedule.visibility(true, T0 + HIDDEN_GRACE_MS - 1);
    expect(schedule.expired(T0 + HIDDEN_GRACE_MS)).toBe(true);

    const returning = createLockSchedule(T0);
    returning.visibility(true, T0);
    returning.visibility(false, T0 + 1_000);
    expect(returning.expired(T0 + HIDDEN_GRACE_MS)).toBe(false);
    // Coming back also counts as activity.
    expect(returning.expired(T0 + 1_000 + AUTO_LOCK_MS)).toBe(true);
  });

  it("keeps the hidden deadline independent of activity", () => {
    const schedule = createLockSchedule(T0);
    schedule.visibility(true, T0);
    // A stray event while hidden must not rescue the grace countdown.
    schedule.activity(T0 + 1_000);
    expect(schedule.expired(T0 + HIDDEN_GRACE_MS)).toBe(true);
  });
});
