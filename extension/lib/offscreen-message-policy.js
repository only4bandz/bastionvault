const MAX_CLIPBOARD_DELAY_MS = 60_000;

function exactKeys(value, keys) {
  return (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

export function authorizedClipboardMessage(
  message,
  sender,
  runtimeId,
  backgroundUrl
) {
  if (
    sender?.id !== runtimeId ||
    sender?.url !== backgroundUrl ||
    sender?.tab !== undefined ||
    message?.target !== "offscreen-clipboard"
  ) {
    return false;
  }
  if (message.type === "CLIP_SCHEDULE_CLEAR") {
    return (
      exactKeys(message, ["target", "type", "delayMs"]) &&
      Number.isInteger(message.delayMs) &&
      message.delayMs >= 0 &&
      message.delayMs <= MAX_CLIPBOARD_DELAY_MS
    );
  }
  if (message.type === "CLIP_CANCEL_CLEAR" || message.type === "CLIP_CLEAR_NOW") {
    return exactKeys(message, ["target", "type"]);
  }
  return false;
}
