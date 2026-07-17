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
  };
}

/** A fired clear proceeds only if no newer clear was scheduled meanwhile. */
export function shouldClear(scheduledToken, currentToken) {
  return scheduledToken === currentToken;
}
