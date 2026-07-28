// Clipboard auto-clear scheduling policy (pure — no chrome/DOM here).
//
// The popup can't own this timer: it closes on click-away (and FILL calls
// window.close()), so its setTimeout never fires and the "clears in 12s"
// promise was empty. The clear is therefore driven by a persistent offscreen
// document; this module holds the ordering logic both sides agree on.

/** Delay before a copied secret is wiped from the clipboard. */
export const CLIPBOARD_CLEAR_MS = 12_000;

/**
 * Tracks the newest scheduled clear so an older pending clear can never wipe a
 * value copied later. Each `schedule()` supersedes the previous one; a fired
 * clear only proceeds if it is still the newest (`shouldClear`).
 */
export function makeClipboardClearScheduler({ setTimer, clearTimer, clearClipboard }) {
  let token = 0;
  let handle;

  return {
    schedule(delayMs = CLIPBOARD_CLEAR_MS) {
      token += 1;
      const mine = token;
      if (handle !== undefined) clearTimer(handle);
      handle = setTimer(() => {
        handle = undefined;
        if (shouldClear(mine, token)) clearClipboard();
      }, delayMs);
      return mine;
    },
    /** Cancel any pending clear (e.g. the vault locked). */
    cancel() {
      token += 1;
      if (handle !== undefined) {
        clearTimer(handle);
        handle = undefined;
      }
    },
    /** Cancel the timer and wipe immediately (for lock/session teardown). */
    clearNow() {
      token += 1;
      if (handle !== undefined) {
        clearTimer(handle);
        handle = undefined;
      }
      clearClipboard();
    },
  };
}

/** A fired clear proceeds only if no newer clear was scheduled meanwhile. */
export function shouldClear(scheduledToken, currentToken) {
  return scheduledToken === currentToken;
}

/**
 * `true` only when the offscreen document acknowledged the command. Anything
 * else — no reply, a rejected send, an `ok: false` — means no timer exists,
 * and the caller must not claim the clipboard will be wiped.
 */
export function clipboardCommandAcknowledged(ack) {
  return Boolean(ack && ack.ok === true);
}

/**
 * The toast for a completed copy. The auto-clear is announced only when the
 * worker confirmed the timer; otherwise the user is told plainly that they
 * must clear it themselves, rather than being promised a wipe that will never
 * happen.
 */
export function copyToastMessage(label, ack) {
  if (!clipboardCommandAcknowledged(ack)) {
    return `${label} copied · auto-clear unavailable, clear it manually`;
  }
  const seconds = Math.round((ack.clearMs ?? CLIPBOARD_CLEAR_MS) / 1000);
  return `${label} copied · clears in ${seconds}s`;
}
