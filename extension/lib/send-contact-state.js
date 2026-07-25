const MAX_CONTACTS = 1_000;
const MAX_CONTACT_DISPLAY_BYTES = 200;
const MAX_DATE_MS = 8_640_000_000_000_000;

const exactRecord = (value, keys) =>
  !!value &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  Object.keys(value).length === keys.length &&
  keys.every((key) => Object.prototype.hasOwnProperty.call(value, key));

function validPublicIdentity(value) {
  return (
    exactRecord(value, ["enc_pub", "sig_pub", "key_version"]) &&
    value.key_version === 1 &&
    Array.isArray(value.enc_pub) &&
    value.enc_pub.length === 32 &&
    value.enc_pub.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255) &&
    Array.isArray(value.sig_pub) &&
    value.sig_pub.length === 32 &&
    value.sig_pub.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
  );
}

export function requireContactsPayload(value) {
  if (!Array.isArray(value) || value.length > MAX_CONTACTS) {
    throw new Error("invalid contacts payload");
  }
  const ids = new Set();
  for (const contact of value) {
    const hasLockMetadata =
      !!contact &&
      typeof contact === "object" &&
      !Array.isArray(contact) &&
      ["lock_enabled", "lock_salt", "lock_kdf"].some((key) =>
        Object.prototype.hasOwnProperty.call(contact, key)
      );
    if (
      !exactRecord(contact, [
        "bastion_id",
        "public",
        "pinFp",
        "display",
        "verified",
        "verified_at",
        "safety_number",
        ...(hasLockMetadata ? ["lock_enabled", "lock_salt", "lock_kdf"] : []),
      ]) ||
      typeof contact.bastion_id !== "string" ||
      !/^[A-Z2-7]{25}[AEIMQUY4]$/.test(contact.bastion_id) ||
      ids.has(contact.bastion_id) ||
      !validPublicIdentity(contact.public) ||
      typeof contact.pinFp !== "string" ||
      !/^[0-9a-f]{64}$/.test(contact.pinFp) ||
      typeof contact.display !== "string" ||
      contact.display.length === 0 ||
      new TextEncoder().encode(contact.display).byteLength > MAX_CONTACT_DISPLAY_BYTES ||
      typeof contact.verified !== "boolean" ||
      (contact.verified_at !== null &&
        (!Number.isSafeInteger(contact.verified_at) ||
          contact.verified_at < 0 ||
          contact.verified_at > MAX_DATE_MS)) ||
      (contact.safety_number !== null &&
        (typeof contact.safety_number !== "string" ||
          !/^[0-9]{60}$/.test(contact.safety_number))) ||
      (contact.verified &&
        (contact.verified_at === null || contact.safety_number === null)) ||
      (!contact.verified && contact.verified_at !== null)
    ) {
      throw new Error("invalid contacts payload");
    }
    if (
      hasLockMetadata &&
      (contact.lock_enabled !== true ||
        typeof contact.lock_salt !== "string" ||
        !/^(?:[A-Za-z0-9+/]{4}){5}[A-Za-z0-9+/][AQgw]==$/.test(contact.lock_salt) ||
        !exactRecord(contact.lock_kdf, ["mem_kib", "iterations", "parallelism"]) ||
        !Number.isSafeInteger(contact.lock_kdf.mem_kib) ||
        contact.lock_kdf.mem_kib < 19 * 1024 ||
        contact.lock_kdf.mem_kib > 128 * 1024 ||
        !Number.isSafeInteger(contact.lock_kdf.iterations) ||
        contact.lock_kdf.iterations < 2 ||
        contact.lock_kdf.iterations > 6 ||
        !Number.isSafeInteger(contact.lock_kdf.parallelism) ||
        contact.lock_kdf.parallelism < 1 ||
        contact.lock_kdf.parallelism > 4)
    ) {
      throw new Error("invalid contacts payload");
    }
    ids.add(contact.bastion_id);
  }
  return value;
}
