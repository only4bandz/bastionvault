export const MAX_CONTENT_ITEM_ID_CHARS = 256;
export const MAX_STAGED_USERNAME_CHARS = 16 * 1024;
export const MAX_STAGED_PASSWORD_CHARS = 128 * 1024;

function boundedString(value, max, allowEmpty = true) {
  return (
    typeof value === "string" &&
    value.length <= max &&
    (allowEmpty || value.length > 0)
  );
}

function exactKeys(message, keys) {
  const allowed = new Set(keys);
  return Object.keys(message).every((key) => allowed.has(key));
}

/**
 * Validate the small set of messages accepted from untrusted page content
 * scripts before they can reach decrypted vault state or session storage.
 */
export function validContentMessage(message) {
  if (!message || typeof message !== "object" || Array.isArray(message)) return false;
  switch (message.type) {
    case "SUGGEST":
    case "PENDING_SAVE":
    case "CLEAR_PENDING":
      return exactKeys(message, ["type"]);
    case "CREDS":
      return (
        exactKeys(message, ["type", "id"]) &&
        boundedString(message.id, MAX_CONTENT_ITEM_ID_CHARS, false)
      );
    case "STAGE_USER":
      return (
        exactKeys(message, ["type", "username"]) &&
        boundedString(message.username, MAX_STAGED_USERNAME_CHARS)
      );
    case "STAGE_SAVE":
      return (
        exactKeys(message, ["type", "username", "password"]) &&
        boundedString(message.username, MAX_STAGED_USERNAME_CHARS) &&
        boundedString(message.password, MAX_STAGED_PASSWORD_CHARS, false)
      );
    case "SAVE_LOGIN":
      return (
        exactKeys(message, ["type", "username"]) &&
        boundedString(message.username, MAX_STAGED_USERNAME_CHARS)
      );
    default:
      return false;
  }
}
