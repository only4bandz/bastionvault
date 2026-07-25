import { describe, expect, it, vi } from "vitest";
import type { VaultItem } from "./types";
import {
  checkPwnedPassword,
  fetchPwnedRange,
  scanPwnedPasswords,
} from "./pwned-passwords";

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
          cache: "no-store",
          headers: { "Add-Padding": "true" },
          redirect: "error",
          referrerPolicy: "no-referrer",
        })
      );
      expect(fetchMock.mock.calls[0][1]).not.toHaveProperty("body");
      expect(findings).toEqual([{ item: ITEM, occurrences: 42 }]);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("checkPwnedPassword sends only the prefix and returns the count", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("1E4C9B93F3F0682250B6CF8331B7EE68FD8:1337\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2")
    );
    try {
      // sha1("password") = 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8
      await expect(checkPwnedPassword("password")).resolves.toBe(1337);
      expect(fetchMock).toHaveBeenCalledWith(
        "https://api.pwnedpasswords.com/range/5BAA6",
        expect.objectContaining({
          credentials: "omit",
          cache: "no-store",
          headers: { "Add-Padding": "true" },
          redirect: "error",
          referrerPolicy: "no-referrer",
        })
      );
      expect(fetchMock.mock.calls[0][1]).not.toHaveProperty("body");
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("checkPwnedPassword returns 0 for an unlisted password", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:7"));
    try {
      await expect(checkPwnedPassword("password")).resolves.toBe(0);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("checkPwnedPassword surfaces service failures", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("", { status: 503 }));
    try {
      await expect(checkPwnedPassword("password")).rejects.toThrow(/HTTP 503/);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("rejects an oversized successful response before parsing it", async () => {
    const fetchMock = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(new Response("x".repeat(128)));
    try {
      await expect(fetchPwnedRange("5BAA6", undefined, 1000, 32)).rejects.toThrow(
        /safe size limit/i
      );
    } finally {
      fetchMock.mockRestore();
    }
  });

  it("aborts a breach request at its local deadline", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener(
            "abort",
            () => reject(init.signal?.reason ?? new DOMException("aborted", "AbortError")),
            { once: true }
          );
        })
    );
    try {
      await expect(fetchPwnedRange("5BAA6", undefined, 1, 1024)).rejects.toMatchObject({
        name: "TimeoutError",
      });
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
