import { describe, expect, it } from "vitest";
import { isVaultItemPayload } from "./vault-item-state";

const valid = {
  id: "item-1",
  type: "login",
  title: "Example",
  username: "alice",
  password: "secret",
  updatedAt: 1,
};

describe("decrypted vault item state", () => {
  it("accepts canonical active and deleted items", () => {
    expect(isVaultItemPayload(valid, "item-1")).toBe(true);
    expect(isVaultItemPayload({ ...valid, deletedAt: 2 }, "item-1")).toBe(true);
  });

  it.each([
    ["storage-id substitution", { ...valid, id: "item-2" }],
    ["unknown fields", { ...valid, injected: true }],
    ["empty title", { ...valid, title: "" }],
    ["unsafe update timestamp", { ...valid, updatedAt: Number.MAX_SAFE_INTEGER }],
    ["negative password timestamp", { ...valid, passwordChangedAt: -1 }],
    ["invalid deletion timestamp", { ...valid, deletedAt: 1.5 }],
    ["oversized URL", { ...valid, url: "x".repeat(8 * 1024 + 1) }],
    ["oversized multibyte folder", { ...valid, folder: "é".repeat(41) }],
    ["oversized plaintext field", { ...valid, notes: "x".repeat(256 * 1024 + 1) }],
  ])("rejects %s", (_name, value) => {
    expect(isVaultItemPayload(value, "item-1")).toBe(false);
  });
});
