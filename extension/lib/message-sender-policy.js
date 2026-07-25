export const POPUP_SENDER = "popup";
export const CONTENT_SENDER = "content";
export const UNKNOWN_SENDER = "unknown";

export function classifyMessageSender(sender, runtimeId, popupUrl) {
  if (!sender || sender.id !== runtimeId || typeof sender.url !== "string") {
    return UNKNOWN_SENDER;
  }
  if (sender.url === popupUrl) return POPUP_SENDER;
  if (!sender.tab || typeof sender.tab !== "object") return UNKNOWN_SENDER;
  try {
    const protocol = new URL(sender.url).protocol;
    if (protocol === "https:" || protocol === "http:") return CONTENT_SENDER;
  } catch {
    // Fall through to the closed state.
  }
  return UNKNOWN_SENDER;
}
