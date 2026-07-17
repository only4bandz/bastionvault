import type { ItemType, VaultItem } from "./types";

export type VaultFilter = "all" | ItemType;
export type VaultSort = "favorites-recent" | "recent" | "oldest" | "name";

function compareText(left: string, right: string): number {
  const a = left.normalize("NFKC").toLowerCase();
  const b = right.normalize("NFKC").toLowerCase();
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
  const query = rawQuery.trim().toLowerCase();
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
      ].some((value) => (value ?? "").toLowerCase().includes(query));
    })
    .sort((left, right) => compareItems(left, right, sort));
}
