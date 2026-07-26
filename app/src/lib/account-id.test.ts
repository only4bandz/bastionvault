import { describe, expect, it } from "vitest";

import { MAX_ACCOUNT_ID_CHARS, canonicalAccountId } from "./account-id";

describe("canonicalAccountId", () => {
  it("canonicalizes the complete ASCII account id", () => {
    expect(canonicalAccountId("  Alice+Vault@Example.COM  ")).toBe(
      "alice+vault@example.com",
    );
  });

  it("rejects ambiguity and Unicode before case folding", () => {
    for (const value of [
      "",
      "alice",
      "@example.com",
      "alice@",
      "alice@@example.com",
      "ali ce@example.com",
      "álîçé@example.com",
      "K@example.com",
      `a@${"x".repeat(MAX_ACCOUNT_ID_CHARS)}`,
    ]) {
      expect(() => canonicalAccountId(value)).toThrow("Invalid email address.");
    }
  });
});
