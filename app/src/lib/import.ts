// CSV import (NordPass / Bitwarden-style exports).
//
// A proper RFC 4180-ish parser: handles quoted fields containing commas,
// newlines and escaped quotes (""), so real passwords with special characters
// survive intact.
import type { ItemType, VaultItem } from "./types";

export const MAX_CSV_BYTES = 5 * 1024 * 1024;
export const MAX_IMPORT_ITEMS = 10_000;
export const MAX_CSV_COLUMNS = 128;
export const MAX_CSV_FIELD_CHARS = 128 * 1024;
export const MAX_IMPORT_ITEM_BYTES = 256 * 1024;

export class CsvImportError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CsvImportError";
  }
}

export function parseCsv(text: string): string[][] {
  if (
    text.length > MAX_CSV_BYTES ||
    new TextEncoder().encode(text).byteLength > MAX_CSV_BYTES
  ) {
    throw new CsvImportError("CSV content exceeds the 5 MiB import limit.");
  }
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  let quotedFieldClosed = false;
  let i = 0;
  const append = (value: string) => {
    field += value;
    if (field.length > MAX_CSV_FIELD_CHARS) {
      throw new CsvImportError("A CSV field exceeds the 128 Ki character limit.");
    }
  };
  const pushField = () => {
    if (row.length >= MAX_CSV_COLUMNS) {
      throw new CsvImportError(`CSV rows cannot contain more than ${MAX_CSV_COLUMNS} columns.`);
    }
    row.push(field);
    field = "";
    quotedFieldClosed = false;
  };
  const pushRow = () => {
    if (rows.length >= MAX_IMPORT_ITEMS + 1) {
      throw new CsvImportError(`CSV files cannot contain more than ${MAX_IMPORT_ITEMS} data rows.`);
    }
    rows.push(row);
    row = [];
  };
  while (i < text.length) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          append('"');
          i += 2;
          continue;
        }
        inQuotes = false;
        quotedFieldClosed = true;
        i++;
        continue;
      }
      append(c);
      i++;
      continue;
    }
    if (quotedFieldClosed) {
      if (c === " " || c === "\t") {
        i++;
      } else if (c === ",") {
        pushField();
        i++;
      } else if (c === "\r" || c === "\n") {
        pushField();
        pushRow();
        if (c === "\r" && text[i + 1] === "\n") i++;
        i++;
      } else {
        throw new CsvImportError("Unexpected content after a quoted CSV field.");
      }
    } else if (c === '"') {
      if (field.length > 0) {
        throw new CsvImportError("A quoted CSV field must start immediately after a delimiter.");
      }
      inQuotes = true;
      i++;
    } else if (c === ",") {
      pushField();
      i++;
    } else if (c === "\r" || c === "\n") {
      pushField();
      pushRow();
      if (c === "\r" && text[i + 1] === "\n") i++;
      i++;
    } else {
      append(c);
      i++;
    }
  }
  if (inQuotes) throw new CsvImportError("The CSV ends inside a quoted field.");
  if (field.length > 0 || row.length > 0 || quotedFieldClosed) {
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

export interface ImportOutcome {
  requested: number;
  imported: number;
}

export type ImportProgress = (imported: number, requested: number) => void;

/** Maps a parsed CSV (with a header row) into vault items. Tolerant of column
 *  order and of missing optional columns. */
export function csvToItems(text: string): ImportResult {
  const rows = parseCsv(text);
  if (rows.length === 0) throw new CsvImportError("CSV must include a header row.");

  const header = rows[0].map((h, index) =>
    (index === 0 ? h.replace(/^\uFEFF/, "") : h).trim().toLowerCase()
  );
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
  if (col.name === -1) {
    throw new CsvImportError('CSV header must include a "name" or "title" column.');
  }
  if (rows.length < 2) return { items: [], skipped: 0 };

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
      item.cardholderName = cell(row, col.cardholder) || undefined;
      item.cardNumber = cell(row, col.cardnumber) || undefined;
      item.cardExp = cell(row, col.exp) || undefined;
      item.cardCvv = cell(row, col.cvc) || undefined;
    }
    if (new TextEncoder().encode(JSON.stringify(item)).byteLength > MAX_IMPORT_ITEM_BYTES) {
      throw new CsvImportError(`CSV row ${r + 1} exceeds the 256 KiB item limit.`);
    }
    items.push(item);
  }
  return { items, skipped };
}
