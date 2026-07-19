import { describe, expect, it, vi } from "vitest";
import type { VaultItem } from "./types";
import { scanPwnedPasswords } from "./pwned-passwords";

const ITEM: VaultItem = {
  id: "login-1",
  type: "login",
  title: "Example",
  password: "password",
  updatedAt: 1,
};

describe("Pwned Passwords scanner", () => {
  it("sends only a padded five-character hash prefix and maps the suffix locally", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0")
    );
    try {
      const findings = await scanPwnedPasswords([ITEM]);
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.pwnedpasswords.com/range/5BAA6",
        expect.objectContaining({
          credentials: "omit",
          headers: { "Add-Padding": "true" },
          referrerPolicy: "no-referrer",
        })
      );
      expect(fetchMock.mock.calls[0][1]).not.toHaveProperty("body");
      expect(findings).toEqual([{ item: ITEM, occurrences: 42 }]);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("never scans trashed items", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch");
    try {
      await expect(scanPwnedPasswords([{ ...ITEM, deletedAt: 2 }])).resolves.toEqual([]);
      expect(fetchMock).not.toHaveBeenCalled();
    } finally {
      fetchMock.mockRestore();
    }
  });
});
