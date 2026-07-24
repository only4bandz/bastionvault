import { describe, expect, it } from "vitest";
import { escapeFormulaPrefix, stripFormulaPrefix } from "./csv-guard";
import { itemsToCsv } from "./export";
import { csvToItems } from "./import";
import type { VaultItem } from "./types";

describe("escapeFormulaPrefix", () => {
  it.each(["=cmd|' /C calc'!A0", "+1234", "-secret", "@import", "\tx", "\rx"])(
    "neutralizes %j",
    (value) => {
      expect(escapeFormulaPrefix(value)).toBe(`'${value}`);
    }
  );

  it("leaves ordinary values untouched", () => {
    for (const value of ["hunter2", "a=b", "", "'quoted'", "1+1", "user@example.com"]) {
      expect(escapeFormulaPrefix(value)).toBe(value);
    }
  });
});

describe("stripFormulaPrefix", () => {
  it("is the exact inverse of escapeFormulaPrefix", () => {
    for (const value of ["=formula", "+x", "-x", "@x", "normal", "'literal", "''=x"]) {
      expect(stripFormulaPrefix(escapeFormulaPrefix(value))).toBe(value);
    }
  });

  it("keeps genuine leading apostrophes", () => {
    expect(stripFormulaPrefix("'twas")).toBe("'twas");
    expect(stripFormulaPrefix("'")).toBe("'");
  });
});

describe("export → import round trip with formula-leading values", () => {
  it("preserves a password starting with = and never emits a bare formula cell", () => {
    const item: VaultItem = {
      id: "x",
      type: "login",
      title: "=HYPERLINK evil",
      username: "@user",
      password: "=cmd|' /C calc'!A0",
      updatedAt: 1_700_000_000_000,
    };
    const csv = itemsToCsv([item]);
    for (const line of csv.split("\r\n").slice(1)) {
      for (const field of line.split(",")) {
        const unquoted = field.replace(/^"|"$/g, "");
        expect(unquoted).not.toMatch(/^[=+@]|^-\d/);
      }
    }
    const reimported = csvToItems(csv);
    expect(reimported.items).toHaveLength(1);
    expect(reimported.items[0].title).toBe("=HYPERLINK evil");
    expect(reimported.items[0].username).toBe("@user");
    expect(reimported.items[0].password).toBe("=cmd|' /C calc'!A0");
  });
});
