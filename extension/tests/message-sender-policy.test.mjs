import assert from "node:assert/strict";
import test from "node:test";

import {
  CONTENT_SENDER,
  POPUP_SENDER,
  UNKNOWN_SENDER,
  classifyMessageSender,
} from "../lib/message-sender-policy.js";

const runtimeId = "extension-id";
const popupUrl = "chrome-extension://extension-id/popup.html";

test("grants privileged messaging only to the exact popup resource", () => {
  assert.equal(
    classifyMessageSender({ id: runtimeId, url: popupUrl }, runtimeId, popupUrl),
    POPUP_SENDER
  );
  for (const sender of [
    { id: runtimeId, url: "chrome-extension://extension-id/options.html" },
    { id: runtimeId, url: "chrome-extension://extension-id/offscreen.html" },
    { id: "another-extension", url: popupUrl },
    { id: runtimeId, url: `${popupUrl}?forged=1` },
  ]) {
    assert.equal(
      classifyMessageSender(sender, runtimeId, popupUrl),
      UNKNOWN_SENDER
    );
  }
});

test("recognizes only same-extension web content scripts", () => {
  assert.equal(
    classifyMessageSender(
      { id: runtimeId, url: "https://example.com/login", tab: { id: 1 } },
      runtimeId,
      popupUrl
    ),
    CONTENT_SENDER
  );
  for (const sender of [
    { id: runtimeId, url: "https://example.com/login" },
    { id: runtimeId, url: "file:///tmp/login.html", tab: { id: 1 } },
    { id: "another-extension", url: "https://example.com", tab: { id: 1 } },
    null,
  ]) {
    assert.equal(
      classifyMessageSender(sender, runtimeId, popupUrl),
      UNKNOWN_SENDER
    );
  }
});
