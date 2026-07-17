// OS-lock integration policy.
//
// The keep-unlocked window can legitimately span hours, but an unlocked vault
// must not outlive the user's presence at the machine: when the OS session
// locks, Bastion locks. Plain "idle" (no input for N seconds) deliberately
// does NOT lock — the user may be reading a page with the vault open, and the
// auto-lock alarm already bounds the session.

/** Seconds of inactivity before chrome.idle reports "idle" (API minimum 15). */
export const IDLE_DETECTION_SECONDS = 300;

/** `true` when a chrome.idle state transition must lock the vault. */
export function shouldLockOnIdleState(state) {
  return state === "locked";
}
