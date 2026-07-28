// When an unlocked vault must lock itself.
//
// Two independent deadlines: prolonged inactivity, and the tab having been
// genuinely hidden for a grace period. Both are kept as absolute wall-clock
// timestamps rather than `setTimeout` handles, for two reasons:
//
//   1. A `setTimeout` is re-created whenever the effect that owns it re-runs.
//      In App.tsx the auto-lock effect depended on `lock`, whose identity
//      changes on every session-token rotation — and rotation runs on the
//      SAME 10-minute period as the idle deadline. Each rotation therefore
//      pushed the idle deadline out afresh, so whether an idle vault ever
//      locked came down to a race. A deadline the schedule owns survives any
//      number of re-mounts: re-arming requires actual user activity.
//
//   2. `setTimeout` counts down in suspended time on some platforms and not
//      others. Comparing against the wall clock means a laptop that sleeps
//      past its deadline locks on the first tick after waking.

export const AUTO_LOCK_MS = 10 * 60 * 1000;
export const HIDDEN_GRACE_MS = 30 * 1000;
/** How often the deadlines are compared against the clock. */
export const LOCK_TICK_MS = 5 * 1000;

export interface LockScheduleOptions {
  autoLockMs?: number;
  hiddenGraceMs?: number;
}

export interface LockSchedule {
  /** User activity: pushes the idle deadline out. */
  activity(now: number): void;
  /** Tab visibility changed. Hiding arms the grace deadline exactly once. */
  visibility(hidden: boolean, now: number): void;
  /** `true` once either deadline has passed. */
  expired(now: number): boolean;
}

export function createLockSchedule(
  now: number,
  { autoLockMs = AUTO_LOCK_MS, hiddenGraceMs = HIDDEN_GRACE_MS }: LockScheduleOptions = {}
): LockSchedule {
  let idleDeadline = now + autoLockMs;
  let hiddenDeadline: number | null = null;

  return {
    activity(at: number): void {
      idleDeadline = at + autoLockMs;
    },
    visibility(hidden: boolean, at: number): void {
      if (!hidden) {
        // Coming back counts as activity, and clears the grace deadline.
        hiddenDeadline = null;
        idleDeadline = at + autoLockMs;
        return;
      }
      // Arm once: re-firing `visibilitychange` while already hidden must not
      // extend a countdown that is already running.
      hiddenDeadline ??= at + hiddenGraceMs;
    },
    expired(at: number): boolean {
      return at >= idleDeadline || (hiddenDeadline !== null && at >= hiddenDeadline);
    },
  };
}
