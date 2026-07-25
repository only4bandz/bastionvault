import { describe, expect, it } from "vitest";
import { relativeItemTime } from "./item-time";

describe("relativeItemTime", () => {
  it("formats stable compact time buckets", () => {
    const now = 2_000_000;
    expect(relativeItemTime(now - 30_000, now)).toBe("just now");
    expect(relativeItemTime(now - 5 * 60_000, now)).toBe("5m ago");
    expect(relativeItemTime(now - 3 * 3_600_000, now)).toBe("3h ago");
    expect(relativeItemTime(now - 2 * 86_400_000, now)).toBe("2d ago");
  });

  it("coarsens long gaps into weeks, months and years", () => {
    const now = 2_000_000_000_000;
    const day = 86_400_000;
    expect(relativeItemTime(now - 13 * day, now)).toBe("13d ago");
    expect(relativeItemTime(now - 14 * day, now)).toBe("2w ago");
    expect(relativeItemTime(now - 45 * day, now)).toBe("6w ago");
    expect(relativeItemTime(now - 61 * day, now)).toBe("2mo ago");
    expect(relativeItemTime(now - 300 * day, now)).toBe("9mo ago");
    expect(relativeItemTime(now - 366 * day, now)).toBe("1y ago");
    expect(relativeItemTime(now - 985 * day, now)).toBe("2y ago");
  });

  it("never skips a bucket at a boundary", () => {
    const now = 2_000_000_000_000;
    const seen = new Set<string>();
    for (let days = 0; days <= 800; days++) {
      seen.add(relativeItemTime(now - days * 86_400_000, now).replace(/\d+/, ""));
    }
    expect([...seen].sort()).toEqual(["d ago", "just now", "mo ago", "w ago", "y ago"]);
  });

  it("clamps future timestamps and rejects non-finite input", () => {
    expect(relativeItemTime(2_000, 1_000)).toBe("just now");
    expect(relativeItemTime(Number.NaN, 1_000)).toBe("unknown");
  });
});
