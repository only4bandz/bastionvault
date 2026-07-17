// Offscreen document — owns the clipboard-clear timer.
//
// It runs independently of the popup (which closes on click-away), so the
// "clears in 12s" promise is actually kept. It receives ONLY a schedule
// signal — never any plaintext or hash — and, after the delay, unconditionally
// overwrites the clipboard with an empty string. Clearing unconditionally
// (rather than read-compare, which needs document focus the offscreen doc
// lacks) matches the web app's documented trade-off: a lingering secret is a
// worse outcome than a lost non-secret snippet. Newer copies supersede older
// pending clears via the scheduler's token.

import { makeClipboardClearScheduler } from "./lib/clipboard-clear.js";

const scheduler = makeClipboardClearScheduler({
  setTimer: (fn, ms) => setTimeout(fn, ms),
  clearTimer: (handle) => clearTimeout(handle),
  clearClipboard: () => {
    navigator.clipboard.writeText("").catch(() => {
      // Best-effort: nothing more we can safely do without focus.
    });
  },
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.target !== "offscreen-clipboard") return false;
  if (msg.type === "CLIP_SCHEDULE_CLEAR") {
    scheduler.schedule(msg.delayMs);
    sendResponse({ ok: true });
  } else if (msg.type === "CLIP_CANCEL_CLEAR") {
    scheduler.cancel();
    sendResponse({ ok: true });
  }
  return false;
});
