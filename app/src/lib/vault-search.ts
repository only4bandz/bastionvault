import type { ItemType, VaultItem } from "./types";

export type VaultFilter = "all" | ItemType;

/**
 * Filter only on display metadata. Secret-bearing fields such as passwords,
 * secure notes, card numbers, and CVVs must never become search indexes.
 */
export function filterVaultItems(
  items: VaultItem[],
  filter: VaultFilter,
  rawQuery: string,
  favoritesOnly = false
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
    .sort(
      (left, right) =>
        Number(right.favorite ?? false) - Number(left.favorite ?? false) ||
        right.updatedAt - left.updatedAt
    );
}
