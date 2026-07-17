import { describe, expect, it } from "vitest";
import type { VaultItem } from "./types";
import { partitionImportItems } from "./import-dedup";

const login = (id: string, password = "secret"): VaultItem => ({
  id,
  type: "login",
  title: "GitHub",
  username: "general",
  password,
  updatedAt: Number(id.replace(/\D/g, "")) || 1,
});

describe("partitionImportItems", () => {
  it("ignores IDs and timestamps when finding exact duplicates", () => {
    const result = partitionImportItems([login("import-2")], [login("existing-1")]);
    expect(result.unique).toEqual([]);
    expect(result.duplicates).toHaveLength(1);
  });

  it("does not merge entries whose secret content differs", () => {
    const result = partitionImportItems([login("import-2", "new-secret")], [login("existing-1")]);
    expect(result.unique).toHaveLength(1);
    expect(result.duplicates).toEqual([]);
  });

  it("deduplicates repeated rows within the same import", () => {
    const result = partitionImportItems([login("1"), login("2")], []);
    expect(result.unique).toHaveLength(1);
    expect(result.duplicates).toHaveLength(1);
  });
});
