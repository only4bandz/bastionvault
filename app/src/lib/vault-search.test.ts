import { describe, expect, it } from "vitest";
import type { VaultItem } from "./types";
import { filterVaultItems } from "./vault-search";

const ITEMS: VaultItem[] = [
  {
    id: "login",
    type: "login",
    title: "GitHub",
    username: "general@example.com",
    password: "login-secret",
    url: "https://github.com",
    notes: "login-note-secret",
    updatedAt: 2,
  },
  {
    id: "note",
    type: "note",
    title: "Recovery plan",
    notes: "note-body-secret",
    updatedAt: 3,
  },
  {
    id: "card",
    type: "card",
    title: "Operations card",
    cardNumber: "4111111111111111",
    cardCvv: "123",
    updatedAt: 1,
  },
];

describe("filterVaultItems", () => {
  it("matches display metadata case-insensitively and sorts newest first", () => {
    expect(filterVaultItems(ITEMS, "all", "").map((item) => item.id)).toEqual([
      "note",
      "login",
      "card",
    ]);
    expect(filterVaultItems(ITEMS, "all", "GENERAL").map((item) => item.id)).toEqual([
      "login",
    ]);
    expect(filterVaultItems(ITEMS, "all", "github.com").map((item) => item.id)).toEqual([
      "login",
    ]);
  });

  it("applies the selected item-type filter", () => {
    expect(filterVaultItems(ITEMS, "card", "").map((item) => item.id)).toEqual(["card"]);
    expect(filterVaultItems(ITEMS, "note", "github")).toEqual([]);
  });

  it.each(["login-secret", "login-note-secret", "note-body-secret", "4111111111111111", "123"])(
    "never matches secret-bearing value %s",
    (secret) => {
      expect(filterVaultItems(ITEMS, "all", secret)).toEqual([]);
    }
  );
});

it("sorts favorites first, then by recency", () => {
  const items = [
    { id: "a", type: "login", title: "Newest", updatedAt: 300 },
    { id: "b", type: "login", title: "Starred old", updatedAt: 100, favorite: true },
    { id: "c", type: "login", title: "Middle", updatedAt: 200 },
    { id: "d", type: "login", title: "Starred new", updatedAt: 250, favorite: true },
  ] as VaultItem[];
  expect(filterVaultItems(items, "all", "").map((i) => i.id)).toEqual(["d", "b", "a", "c"]);
});

it("matches displayed card metadata but never secret fields", () => {
  const card: VaultItem = {
    id: "card-meta",
    type: "card",
    title: "Everyday",
    cardholderName: "General Example",
    cardNumber: "4111111111111111",
    cardCvv: "987",
    cardBrand: "visa",
    cardBank: "CIBC",
    cardType: "debit",
    notes: "hidden words",
    updatedAt: 1,
  };
  expect(filterVaultItems([card], "all", "visa")).toHaveLength(1);
  expect(filterVaultItems([card], "all", "general example")).toHaveLength(1);
  expect(filterVaultItems([card], "all", "cibc")).toHaveLength(1);
  expect(filterVaultItems([card], "all", "debit")).toHaveLength(1);
  expect(filterVaultItems([card], "all", "4111")).toHaveLength(0);
  expect(filterVaultItems([card], "all", "987")).toHaveLength(0);
  expect(filterVaultItems([card], "all", "hidden")).toHaveLength(0);
});
