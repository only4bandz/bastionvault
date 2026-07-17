// CSV export — the mirror of import.ts. The column set is chosen so a file
// exported here re-imports through csvToItems() without loss of the fields
// both sides understand (name/type/url/username/password/note/card fields).
//
// ⚠️ The produced file is UNENCRYPTED plaintext. The UI must warn before
// handing it to the user, and never write it anywhere itself.
import type { VaultItem } from "./types";

export const EXPORT_HEADER = [
  "name",
  "type",
  "url",
  "username",
  "password",
  "note",
  "cardholdername",
  "cardnumber",
  "expirydate",
  "cvc",
] as const;

/** RFC 4180 quoting: only when the value needs it, doubling inner quotes. */
function csvField(value: string): string {
  return /[",\n\r]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

export function itemsToCsv(items: VaultItem[]): string {
  const lines = [EXPORT_HEADER.join(",")];
  for (const item of items) {
    lines.push(
      [
        item.title,
        item.type,
        item.url ?? "",
        item.username ?? "",
        item.password ?? "",
        item.notes ?? "",
        item.cardholderName ?? "",
        item.cardNumber ?? "",
        item.cardExp ?? "",
        item.cardCvv ?? "",
      ]
        .map(csvField)
        .join(",")
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}

export function exportFilename(now: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `bastion-export-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}.csv`;
}

/** Hands the CSV to the browser as a download. Returns true on success. */
export function downloadCsv(csv: string, filename: string): boolean {
  try {
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
    URL.revokeObjectURL(url);
    return true;
  } catch {
    return false;
  }
}
