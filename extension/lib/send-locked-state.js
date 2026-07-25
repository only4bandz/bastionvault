const MAX_LOCKED_BODY_BYTES = 512 * 1024;
const MAX_UNIX_SECONDS = 253_402_300_799;

const exactRecord = (value, keys) =>
  !!value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));

function canonicalBase64Length(value) {
  if (
    typeof value !== "string" ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/][AQgw]==|[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=)?$/.test(value)
  ) {
    return null;
  }
  const padding = value.endsWith("==") ? 2 : value.endsWith("=") ? 1 : 0;
  return (value.length / 4) * 3 - padding;
}

const exactBase64Bytes = (value, size) => canonicalBase64Length(value) === size;

export function isLockedSendRecord(value, storageId) {
  if (
    !exactRecord(value, [
      "v",
      "local_id",
      "contact_id",
      "message_id",
      "lock_commit",
      "body",
      "created_at",
    ]) ||
    value.v !== 1 ||
    !exactBase64Bytes(value.local_id, 16) ||
    storageId !== `bastion:send-locked:${value.local_id}` ||
    typeof value.contact_id !== "string" ||
    !/^[A-Z2-7]{25}[AEIMQUY4]$/.test(value.contact_id) ||
    !exactBase64Bytes(value.message_id, 16) ||
    !exactBase64Bytes(value.lock_commit, 32) ||
    !Number.isSafeInteger(value.created_at) ||
    value.created_at < 0 ||
    value.created_at > MAX_UNIX_SECONDS ||
    !exactRecord(value.body, ["v", "nonce", "ct"]) ||
    value.body.v !== 1 ||
    !exactBase64Bytes(value.body.nonce, 24)
  ) {
    return false;
  }
  const bodyBytes = canonicalBase64Length(value.body.ct);
  return bodyBytes !== null && bodyBytes >= 16 && bodyBytes <= MAX_LOCKED_BODY_BYTES;
}

export function requireLockedRecordContacts(records, contacts) {
  const messageIds = new Set();
  for (const record of records) {
    if (
      messageIds.has(record.message_id) ||
      !contacts.some(
        (contact) =>
          contact.bastion_id === record.contact_id && contact.lock_enabled === true
      )
    ) {
      throw new Error("invalid locked Send state");
    }
    messageIds.add(record.message_id);
  }
  return records;
}
