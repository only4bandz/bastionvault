// CSV export — the mirror of import.ts. The column set is chosen so a file
// exported here re-imports through csvToItems() without loss of the fields
// both sides understand (name/type/url/username/password/note/card fields).
//
// ⚠️ The produced file is UNENCRYPTED plaintext. The UI must warn before
// handing it to the user, and never write it anywhere itself.
import type { VaultItem } from "./types";
import { escapeFormulaPrefix } from "./csv-guard";

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
  "favorite",
  "updatedat",
  "passwordchangedat",
  "cardbrand",
  "cardbank",
  "cardbankdomain",
  "cardtype",
  "folder",
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
        item.favorite === undefined ? "" : String(item.favorite),
        String(item.updatedAt),
        item.passwordChangedAt === undefined ? "" : String(item.passwordChangedAt),
        item.cardBrand ?? "",
        item.cardBank ?? "",
        item.cardBankDomain ?? "",
        item.cardType ?? "",
        item.folder ?? "",
      ]
        .map((value) => csvField(escapeFormulaPrefix(value)))
        .join(",")
    );
  }
  return `${lines.join("\r\n")}\r\n`;
}

export function exportFilename(now: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `bastion-export-${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}.csv`;
}

/**
 * How long the plaintext blob URL is allowed to stay resolvable.
 *
 * Revoking synchronously after `click()` is a real bug in Firefox and Safari:
 * the download has not been handed to the browser's download manager yet, so
 * the fetch of the just-revoked URL fails and the user gets nothing — while
 * `downloadCsv` cheerfully returns true. Revoking on the next macrotask is the
 * standard fix, and one tick is the shortest window that actually works.
 */
const OBJECT_URL_LIFETIME_MS = 0;

/**
 * Hands the CSV to the browser as a download. Returns true on success.
 *
 * ⚠️ The blob behind the returned URL is the entire vault in plaintext. It is
 * revoked unconditionally — on the success path and on the throw path — so a
 * `blob:` URL that resolves to every password in the vault never outlives the
 * click that created it. Any code holding that string afterwards gets nothing.
 */
export function downloadCsv(csv: string, filename: string): boolean {
  let url: string | undefined;
  let anchor: HTMLAnchorElement | undefined;
  try {
    url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    // Firefox only dispatches the download for an anchor in the document.
    anchor.style.display = "none";
    anchor.rel = "noopener";
    document.body.append(anchor);
    anchor.click();
    return true;
  } catch {
    return false;
  } finally {
    anchor?.remove();
    if (url !== undefined) {
      const revoked = url;
      setTimeout(() => URL.revokeObjectURL(revoked), OBJECT_URL_LIFETIME_MS);
    }
  }
}
