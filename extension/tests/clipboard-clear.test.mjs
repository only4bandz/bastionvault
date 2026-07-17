import assert from "node:assert/strict";
import test from "node:test";

import {
  CLIPBOARD_CLEAR_MS,
  makeClipboardClearScheduler,
  shouldClear,
} from "../lib/clipboard-clear.js";

function fakeTimers() {
  let now = 0;
  const pending = new Map();
  let id = 0;
  return {
    setTimer: (fn, delay) => {
      const handle = ++id;
      pending.set(handle, { fn, at: now + delay });
      return handle;
    },
    clearTimer: (handle) => pending.delete(handle),
    advance: (ms) => {
      now += ms;
      for (const [handle, t] of [...pending.entries()]) {
        if (t.at <= now) {
          pending.delete(handle);
          t.fn();
        }
      }
    },
  };
}

test("wipes the clipboard after the delay", () => {
  const timers = fakeTimers();
  let cleared = 0;
  const s = makeClipboardClearScheduler({ ...timers, clearClipboard: () => (cleared += 1) });
  s.schedule();
  timers.advance(CLIPBOARD_CLEAR_MS - 1);
  assert.equal(cleared, 0);
  timers.advance(1);
  assert.equal(cleared, 1);
});

test("a newer copy supersedes the older pending clear (exactly one wipe, on time)", () => {
  const timers = fakeTimers();
  let cleared = 0;
  const s = makeClipboardClearScheduler({ ...timers, clearClipboard: () => (cleared += 1) });
  s.schedule();
  timers.advance(CLIPBOARD_CLEAR_MS / 2);
  s.schedule();
  timers.advance(CLIPBOARD_CLEAR_MS / 2); // first deadline passes — must NOT wipe
  assert.equal(cleared, 0);
  timers.advance(CLIPBOARD_CLEAR_MS / 2); // second deadline
  assert.equal(cleared, 1);
});

test("cancel prevents a pending wipe", () => {
  const timers = fakeTimers();
  let cleared = 0;
  const s = makeClipboardClearScheduler({ ...timers, clearClipboard: () => (cleared += 1) });
  s.schedule();
  s.cancel();
  timers.advance(CLIPBOARD_CLEAR_MS * 2);
  assert.equal(cleared, 0);
});

test("shouldClear only fires for the newest token", () => {
  assert.equal(shouldClear(3, 3), true);
  assert.equal(shouldClear(2, 3), false);
});
