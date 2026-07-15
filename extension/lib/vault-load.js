const SEND_IDENTITY_ID = "bastion:send-identity";
const SEND_CONTACTS_ID = "bastion:send-contacts";
const SEND_LOCKED_PREFIX = "bastion:send-locked:";
const SEND_RESERVED_PREFIX = "bastion:send-";
const ITEM_TYPES = new Set(["login", "note", "card"]);
const OPTIONAL_STRING_FIELDS = [
  "username", "password", "url", "cardNumber", "cardExp", "cardCvv",
  "cardBrand", "cardBank", "cardBankDomain", "cardType", "notes",
];

export class VaultIntegrityError extends Error {
  constructor() {
    super("Encrypted vault integrity check failed. No items were loaded.");
    this.name = "VaultIntegrityError";
  }
}

const isRecord = (value) => !!value && typeof value === "object" && !Array.isArray(value);

function isVaultItem(value, storageId) {
  return (
    isRecord(value) &&
    value.id === storageId &&
    ITEM_TYPES.has(value.type) &&
    typeof value.title === "string" &&
    typeof value.updatedAt === "number" &&
    Number.isFinite(value.updatedAt) &&
    OPTIONAL_STRING_FIELDS.every((field) => value[field] === undefined || typeof value[field] === "string") &&
    (value.favorite === undefined || typeof value.favorite === "boolean")
  );
}

function isContact(value) {
  return (
    isRecord(value) &&
    typeof value.bastion_id === "string" &&
    isRecord(value.public) &&
    typeof value.pinFp === "string" &&
    typeof value.display === "string" &&
    typeof value.verified === "boolean" &&
    (value.verified_at === null || typeof value.verified_at === "number") &&
    (value.safety_number === null || typeof value.safety_number === "string")
  );
}

/** Decrypt and validate the complete vault, or expose nothing. */
export function loadVaultState(account, rawItems) {
  if (!isRecord(rawItems)) throw new VaultIntegrityError();

  const items = new Map();
  let contacts = [];
  const lockedRecords = [];
  try {
    for (const [id, blob] of Object.entries(rawItems)) {
      if (id === SEND_IDENTITY_ID) {
        account.load_send_identity(JSON.stringify(blob));
        continue;
      }

      const plaintext = account.decrypt_item(JSON.stringify(blob), id);
      const parsed = JSON.parse(plaintext);
      if (id === SEND_CONTACTS_ID) {
        if (!Array.isArray(parsed) || !parsed.every(isContact)) throw new VaultIntegrityError();
        contacts = parsed;
      } else if (id.startsWith(SEND_LOCKED_PREFIX)) {
        if (!isRecord(parsed)) throw new VaultIntegrityError();
        lockedRecords.push(parsed);
      } else if (id.startsWith(SEND_RESERVED_PREFIX)) {
        throw new VaultIntegrityError();
      } else {
        if (!isVaultItem(parsed, id)) throw new VaultIntegrityError();
        items.set(id, parsed);
      }
    }
  } catch (error) {
    if (error instanceof VaultIntegrityError) throw error;
    throw new VaultIntegrityError();
  }
  return { items, contacts, lockedRecords };
}
