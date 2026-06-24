// CSV import (NordPass / Bitwarden-style exports).
//
// A proper RFC 4180-ish parser: handles quoted fields containing commas,
// newlines and escaped quotes (""), so real passwords with special characters
// survive intact.
import type { ItemType, VaultItem } from "./types";

export function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let i = 0;
  const pushField = () => {
    row.push(field);
    field = "";
  };
  const pushRow = () => {
    rows.push(row);
    row = [];
  };
  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i += 2;
          continue;
        }
        inQuotes = false;
        i++;
        continue;
      }
      field += c;
      i++;
      continue;
    }
    if (c === '"') {
      inQuotes = true;
      i++;
    } else if (c === ",") {
      pushField();
      i++;
    } else if (c === "\r") {
      i++;
    } else if (c === "\n") {
      pushField();
      pushRow();
      i++;
    } else {
      field += c;
      i++;
    }
  }
  if (field.length > 0 || row.length > 0) {
    pushField();
    pushRow();
  }
  // Drop fully-empty rows.
  return rows.filter((r) => r.some((f) => f.trim() !== ""));
}

export interface ImportResult {
  items: VaultItem[];
  skipped: number;
}

/** Maps a parsed CSV (with a header row) into vault items. Tolerant of column
 *  order and of missing optional columns. */
export function csvToItems(text: string): ImportResult {
  const rows = parseCsv(text);
  if (rows.length < 2) return { items: [], skipped: 0 };

  const header = rows[0].map((h) => h.trim().toLowerCase());
  const idx = (...names: string[]) => {
    for (const n of names) {
      const i = header.indexOf(n);
      if (i !== -1) return i;
    }
    return -1;
  };
  const col = {
    name: idx("name", "title"),
    url: idx("url", "website", "uri", "login_uri"),
    username: idx("username", "login_username", "email"),
    password: idx("password", "login_password"),
    note: idx("note", "notes"),
    type: idx("type"),
    cardholder: idx("cardholdername"),
    cardnumber: idx("cardnumber"),
    cvc: idx("cvc", "cvv"),
    exp: idx("expirydate", "expiry"),
  };

  // Trim everything except the password, which is preserved verbatim.
  const cell = (r: string[], i: number) => (i >= 0 && i < r.length ? r[i].trim() : "");
  const raw = (r: string[], i: number) => (i >= 0 && i < r.length ? r[i] : "");

  const items: VaultItem[] = [];
  let skipped = 0;
  for (let r = 1; r < rows.length; r++) {
    const row = rows[r];
    const name = cell(row, col.name);
    if (!name) {
      skipped++;
      continue;
    }
    const t = cell(row, col.type).toLowerCase();
    const type: ItemType =
      t.includes("card") || cell(row, col.cardnumber)
        ? "card"
        : t.includes("note") || t.includes("secure")
          ? "note"
          : "login";

    const item: VaultItem = {
      id: crypto.randomUUID(),
      type,
      title: name,
      notes: cell(row, col.note) || undefined,
      updatedAt: Date.now(),
    };
    if (type === "login") {
      item.username = cell(row, col.username) || undefined;
      item.password = raw(row, col.password) || undefined;
      item.url = cell(row, col.url) || undefined;
    } else if (type === "card") {
      item.cardNumber = cell(row, col.cardnumber) || undefined;
      item.cardExp = cell(row, col.exp) || undefined;
      item.cardCvv = cell(row, col.cvc) || undefined;
    }
    items.push(item);
  }
  return { items, skipped };
}
