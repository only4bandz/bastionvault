import type { VaultItem } from "./types";

const CONTENT_FIELDS: (keyof VaultItem)[] = [
  "type", "title", "username", "password", "url", "cardholderName",
  "cardNumber", "cardExp", "cardCvv", "cardBrand", "cardBank",
  "cardBankDomain", "cardType", "notes",
];

function contentSignature(item: VaultItem): string {
  return JSON.stringify(CONTENT_FIELDS.map((field) => item[field] ?? null));
}

/** Partition exact content duplicates without persisting any derived value. */
export function partitionImportItems(
  imported: VaultItem[],
  existing: VaultItem[]
): { unique: VaultItem[]; duplicates: VaultItem[] } {
  const seen = new Set(existing.map(contentSignature));
  const unique: VaultItem[] = [];
  const duplicates: VaultItem[] = [];
  for (const item of imported) {
    const signature = contentSignature(item);
    if (seen.has(signature)) duplicates.push(item);
    else {
      seen.add(signature);
      unique.push(item);
    }
  }
  return { unique, duplicates };
}
