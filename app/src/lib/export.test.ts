import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { downloadCsv, exportFilename, itemsToCsv } from "./export";
import { csvToItems } from "./import";
import type { VaultItem } from "./types";

const LOGIN: VaultItem = {
  id: "l1",
  type: "login",
  title: 'Bank, "main"',
  username: "alice@example.com",
  password: 'p@ss,word\n"quoted"',
  url: "https://bank.example",
  notes: "line one\nline two",
  favorite: true,
  updatedAt: 1_700_000_000_000,
  passwordChangedAt: 1_600_000_000_000,
  folder: "Personal",
};

const CARD: VaultItem = {
  id: "c1",
  type: "card",
  title: "Visa",
  cardholderName: "General Example",
  cardNumber: "4111 1111 1111 1111",
  cardExp: "12/27",
  cardCvv: "123",
  cardBrand: "visa",
  cardBank: "Example Bank",
  cardBankDomain: "bank.example",
  cardType: "credit",
  updatedAt: 1,
};

const NOTE: VaultItem = {
  id: "n1",
  type: "note",
  title: "Wifi",
  notes: "ssid: home",
  updatedAt: 1,
};

describe("itemsToCsv", () => {
  it("escapes commas, quotes and newlines per RFC 4180", () => {
    const csv = itemsToCsv([LOGIN]);
    expect(csv).toContain('"Bank, ""main"""');
    expect(csv).toContain('"p@ss,word\n""quoted"""');
  });

  it("round-trips through the importer without losing shared fields", () => {
    const { items, skipped } = csvToItems(itemsToCsv([LOGIN, CARD, NOTE]));
    expect(skipped).toBe(0);
    expect(items).toHaveLength(3);

    const [login, card, note] = items;
    expect(login).toMatchObject({
      type: "login",
      title: LOGIN.title,
      username: LOGIN.username,
      password: LOGIN.password,
      url: LOGIN.url,
      notes: LOGIN.notes,
      favorite: true,
      updatedAt: LOGIN.updatedAt,
      passwordChangedAt: LOGIN.passwordChangedAt,
      folder: LOGIN.folder,
    });
    expect(card).toMatchObject({
      type: "card",
      title: CARD.title,
      cardholderName: CARD.cardholderName,
      cardNumber: CARD.cardNumber,
      cardExp: CARD.cardExp,
      cardCvv: CARD.cardCvv,
      cardBrand: CARD.cardBrand,
      cardBank: CARD.cardBank,
      cardBankDomain: CARD.cardBankDomain,
      cardType: CARD.cardType,
    });
    expect(note).toMatchObject({ type: "note", title: NOTE.title, notes: NOTE.notes });
  });

  it("names the file with the export date", () => {
    expect(exportFilename(new Date(2026, 6, 17))).toBe("bastion-export-2026-07-17.csv");
  });
});

describe("downloadCsv", () => {
  const created: string[] = [];
  const revoked: string[] = [];

  beforeEach(() => {
    // Fake timers throughout: the deferred revoke must never leak into a
    // later test and be recorded against its stub.
    vi.useFakeTimers();
    created.length = 0;
    revoked.length = 0;
    vi.stubGlobal("URL", {
      createObjectURL: () => {
        const url = `blob:stub/${created.length}`;
        created.push(url);
        return url;
      },
      revokeObjectURL: (url: string) => revoked.push(url),
    });
  });

  afterEach(() => {
    vi.runAllTimers();
    vi.useRealTimers();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("clicks an in-document anchor and leaves no node behind", () => {
    const clicked: (string | null)[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement
    ) {
      // The anchor must be attached at click time, or Firefox drops it.
      clicked.push(this.isConnected ? this.download : null);
    });

    expect(downloadCsv("a,b\r\n", "bastion-export-2026-07-25.csv")).toBe(true);

    expect(clicked).toEqual(["bastion-export-2026-07-25.csv"]);
    expect(document.querySelector("a")).toBeNull();
  });

  it("revokes the plaintext blob URL, but only after the click has been handed off", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});

    downloadCsv("secret,csv\r\n", "vault.csv");

    // Revoking synchronously would break the download in Firefox/Safari.
    expect(created).toHaveLength(1);
    expect(revoked).toEqual([]);
    vi.runAllTimers();
    expect(revoked).toEqual(created);
  });

  it("revokes the blob URL and reports failure when the click throws", () => {
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(downloadCsv("secret,csv\r\n", "vault.csv")).toBe(false);

    expect(document.querySelector("a")).toBeNull();
    vi.runAllTimers();
    expect(revoked).toEqual(created);
  });
});
