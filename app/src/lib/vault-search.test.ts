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
