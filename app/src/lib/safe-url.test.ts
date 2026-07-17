import { describe, expect, it } from "vitest";
import { safeWebsiteUrl } from "./safe-url";

describe("safeWebsiteUrl", () => {
  it("accepts only absolute HTTP and HTTPS destinations", () => {
    expect(safeWebsiteUrl("https://example.com/login")).toBe("https://example.com/login");
    expect(safeWebsiteUrl(" http://example.com ")).toBe("http://example.com/");
    expect(safeWebsiteUrl("example.com")).toBeNull();
  });

  it.each([
    "javascript:alert(1)",
    "data:text/html,hello",
    "file:///etc/passwd",
    "https://user:secret@example.com",
    "not a url",
  ])("rejects unsafe destination %s", (value) => {
    expect(safeWebsiteUrl(value)).toBeNull();
  });
});
