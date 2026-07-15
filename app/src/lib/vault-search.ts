import type { ItemType, VaultItem } from "./types";

export type VaultFilter = "all" | ItemType;

/**
 * Filter only on display metadata. Secret-bearing fields such as passwords,
 * secure notes, card numbers, and CVVs must never become search indexes.
 */
export function filterVaultItems(
  items: VaultItem[],
  filter: VaultFilter,
  rawQuery: string
): VaultItem[] {
  const query = rawQuery.trim().toLowerCase();
  return items
    .filter((item) => filter === "all" || item.type === filter)
    .filter((item) => {
      if (!query) return true;
      return [item.title, item.username, item.url].some((value) =>
        (value ?? "").toLowerCase().includes(query)
      );
    })
    .sort((left, right) => right.updatedAt - left.updatedAt);
}
