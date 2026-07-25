const MAX_DATE_MS = 8_640_000_000_000_000;
const MAX_TITLE_BYTES = 512;
const MAX_FOLDER_BYTES = 80;
const MAX_URL_BYTES = 8 * 1024;
const MAX_FIELD_BYTES = 256 * 1024;
const ITEM_TYPES = new Set(["login", "note", "card"]);
const OPTIONAL_STRINGS = [
  "username",
  "password",
  "url",
  "cardNumber",
  "cardholderName",
  "cardExp",
  "cardCvv",
  "cardBrand",
  "cardBank",
  "cardBankDomain",
  "cardType",
  "notes",
  "folder",
];
const ALLOWED_KEYS = new Set([
  "id",
  "type",
  "title",
  "updatedAt",
  ...OPTIONAL_STRINGS,
  "favorite",
  "passwordChangedAt",
  "deletedAt",
]);

const bytes = (value) => new TextEncoder().encode(value).byteLength;
const safeDate = (value) =>
  Number.isSafeInteger(value) && value >= 0 && value <= MAX_DATE_MS;

export function isVaultItemPayload(value, storageId) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !ALLOWED_KEYS.has(key))
  ) {
    return false;
  }
  return (
    value.id === storageId &&
    ITEM_TYPES.has(value.type) &&
    typeof value.title === "string" &&
    value.title.length > 0 &&
    bytes(value.title) <= MAX_TITLE_BYTES &&
    safeDate(value.updatedAt) &&
    OPTIONAL_STRINGS.every((field) => {
      const fieldValue = value[field];
      if (fieldValue === undefined) return true;
      if (typeof fieldValue !== "string") return false;
      const limit =
        field === "folder"
          ? MAX_FOLDER_BYTES
          : field === "url"
            ? MAX_URL_BYTES
            : MAX_FIELD_BYTES;
      return bytes(fieldValue) <= limit;
    }) &&
    (value.favorite === undefined || typeof value.favorite === "boolean") &&
    (value.passwordChangedAt === undefined || safeDate(value.passwordChangedAt)) &&
    (value.deletedAt === undefined || safeDate(value.deletedAt))
  );
}
