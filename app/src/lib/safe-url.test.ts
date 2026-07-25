import { describe, expect, it } from "vitest";
import { isInsecureWebsiteUrl, safeWebsiteUrl } from "./safe-url";

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

describe("isInsecureWebsiteUrl", () => {
  it.each(["http://example.com/login", " http://sub.example.com ", "http://EXAMPLE.com"])(
    "flags cleartext destination %s",
    (value) => {
      expect(isInsecureWebsiteUrl(value)).toBe(true);
    }
  );

  it.each([
    ["HTTPS", "https://example.com/login"],
    ["loopback name", "http://localhost:3000/app"],
    ["loopback IPv4", "http://127.0.0.1:8080"],
    ["loopback IPv6", "http://[::1]:8080"],
    ["a value that is not a usable destination", "example.com"],
    ["a rejected scheme", "javascript:alert(1)"],
    ["an empty field", undefined],
  ])("does not flag %s", (_name, value) => {
    expect(isInsecureWebsiteUrl(value)).toBe(false);
  });
});
