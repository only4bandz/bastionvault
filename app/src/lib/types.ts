export type ItemType = "login" | "note" | "card";

export interface VaultItem {
  id: string;
  type: ItemType;
  title: string;
  // login
  username?: string;
  password?: string;
  url?: string;
  // card
  cardNumber?: string;
  cardExp?: string;
  cardCvv?: string;
  // shared
  notes?: string;
  favorite?: boolean;
  updatedAt: number;
}

export const TYPE_LABEL: Record<ItemType, string> = {
  login: "Login",
  note: "Secure Note",
  card: "Credit Card",
};

/** Deterministic accent color for an item's avatar, from its title. */
export function itemColor(title: string): string {
  const palette = ["#7c6cff", "#3ad29f", "#ff7a59", "#47b5ff", "#f7b955", "#ff5d9e", "#19c3c3"];
  let h = 0;
  for (let i = 0; i < title.length; i++) h = (h * 31 + title.charCodeAt(i)) >>> 0;
  return palette[h % palette.length];
}
