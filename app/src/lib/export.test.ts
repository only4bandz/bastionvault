import { describe, expect, it } from "vitest";
import { exportFilename, itemsToCsv } from "./export";
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
