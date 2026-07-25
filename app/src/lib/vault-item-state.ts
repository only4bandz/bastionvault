import type { VaultItem } from "./types";

const MAX_DATE_MS = 8_640_000_000_000_000;
const MAX_TITLE_BYTES = 512;
const MAX_FOLDER_BYTES = 80;
const MAX_URL_BYTES = 8 * 1024;
const MAX_FIELD_BYTES = 256 * 1024;
const ITEM_TYPES = new Set(["login", "note", "card"]);
const OPTIONAL_STRINGS: (keyof VaultItem)[] = [
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

const bytes = (value: string): number => new TextEncoder().encode(value).byteLength;
const safeDate = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0 && (value as number) <= MAX_DATE_MS;

export function isVaultItemPayload(value: unknown, storageId: string): value is VaultItem {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !ALLOWED_KEYS.has(key))
  ) {
    return false;
  }
  const item = value as Partial<VaultItem>;
  if (
    item.id !== storageId ||
    typeof item.type !== "string" ||
    !ITEM_TYPES.has(item.type) ||
    typeof item.title !== "string" ||
    item.title.length === 0 ||
    bytes(item.title) > MAX_TITLE_BYTES ||
    !safeDate(item.updatedAt) ||
    OPTIONAL_STRINGS.some((field) => {
      const fieldValue = item[field];
      if (fieldValue === undefined) return false;
      if (typeof fieldValue !== "string") return true;
      const limit =
        field === "folder"
          ? MAX_FOLDER_BYTES
          : field === "url"
            ? MAX_URL_BYTES
            : MAX_FIELD_BYTES;
      return bytes(fieldValue) > limit;
    }) ||
    (item.favorite !== undefined && typeof item.favorite !== "boolean") ||
    (item.passwordChangedAt !== undefined && !safeDate(item.passwordChangedAt)) ||
    (item.deletedAt !== undefined && !safeDate(item.deletedAt))
  ) {
    return false;
  }
  return true;
}
