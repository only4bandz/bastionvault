import assert from "node:assert/strict";
import test from "node:test";

import { authorizedClipboardMessage } from "../lib/offscreen-message-policy.js";

const runtimeId = "extension-id";
const backgroundUrl = "chrome-extension://extension-id/background.js";
const background = { id: runtimeId, url: backgroundUrl };

test("accepts only bounded clipboard commands from the exact service worker", () => {
  assert.equal(
    authorizedClipboardMessage(
      { target: "offscreen-clipboard", type: "CLIP_SCHEDULE_CLEAR", delayMs: 12_000 },
      background,
      runtimeId,
      backgroundUrl
    ),
    true
  );
  assert.equal(
    authorizedClipboardMessage(
      { target: "offscreen-clipboard", type: "CLIP_CLEAR_NOW" },
      background,
      runtimeId,
      backgroundUrl
    ),
    true
  );
});

test("rejects content scripts, extension pages, malformed commands, and extra fields", () => {
  const command = { target: "offscreen-clipboard", type: "CLIP_CLEAR_NOW" };
  for (const [message, sender] of [
    [command, { id: runtimeId, url: "https://attacker.example", tab: { id: 1 } }],
    [command, { id: runtimeId, url: "chrome-extension://extension-id/popup.html" }],
    [{ ...command, extra: true }, background],
    [
      { target: "offscreen-clipboard", type: "CLIP_SCHEDULE_CLEAR", delayMs: 60_001 },
      background,
    ],
    [{ target: "offscreen-clipboard", type: "UNKNOWN" }, background],
  ]) {
    assert.equal(
      authorizedClipboardMessage(message, sender, runtimeId, backgroundUrl),
      false
    );
  }
});
