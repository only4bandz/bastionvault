import type { ItemType, VaultItem } from "./types";

export type VaultFilter = "all" | ItemType;
export type VaultSort = "favorites-recent" | "recent" | "oldest" | "name";

/**
 * Fold a value to the form both the query and the indexed fields are compared
 * in: unicode-normalized, diacritic-stripped, case-folded.
 *
 * Two different problems are solved here. First, "é" has two equally valid
 * encodings (precomposed U+00E9, or "e" + U+0301) and which one lands in the
 * vault depends on the keyboard, the OS and the site the value was imported
 * from — a substring match between the two forms simply fails. Second, someone
 * searching a vault does not switch keyboard layouts to find "Café Réservation";
 * typing "cafe reservation" has to work.
 */
export function searchKey(value: string): string {
  return value
    .normalize("NFKD")
    .replace(/\p{M}+/gu, "")
    .normalize("NFKC")
    .toLowerCase();
}

function compareText(left: string, right: string): number {
  const a = searchKey(left);
  const b = searchKey(right);
  return a < b ? -1 : a > b ? 1 : 0;
}

function compareItems(left: VaultItem, right: VaultItem, sort: VaultSort): number {
  const byId = compareText(left.id, right.id);
  if (sort === "name") return compareText(left.title, right.title) || byId;
  if (sort === "oldest") return left.updatedAt - right.updatedAt || byId;
  if (sort === "recent") return right.updatedAt - left.updatedAt || byId;
  return (
    Number(right.favorite ?? false) - Number(left.favorite ?? false) ||
    right.updatedAt - left.updatedAt ||
    byId
  );
}

/**
 * Filter only on display metadata. Secret-bearing fields such as passwords,
 * secure notes, card numbers, and CVVs must never become search indexes.
 */
export function filterVaultItems(
  items: VaultItem[],
  filter: VaultFilter,
  rawQuery: string,
  favoritesOnly = false,
  sort: VaultSort = "favorites-recent"
): VaultItem[] {
  const query = searchKey(rawQuery.trim());
  return items
    .filter((item) => filter === "all" || item.type === filter)
    .filter((item) => !favoritesOnly || item.favorite === true)
    .filter((item) => {
      if (!query) return true;
      // Card brand/bank/type are display metadata the list already renders in
      // clear — indexing them is safe; numbers/CVVs/notes stay unindexed.
      return [
        item.title,
        item.username,
        item.url,
        item.cardholderName,
        item.cardBrand,
        item.cardBank,
        item.cardType,
        item.folder,
      ].some((value) => searchKey(value ?? "").includes(query));
    })
    .sort((left, right) => compareItems(left, right, sort));
}
