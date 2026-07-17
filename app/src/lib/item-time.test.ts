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

  it("clamps future timestamps and rejects non-finite input", () => {
    expect(relativeItemTime(2_000, 1_000)).toBe("just now");
    expect(relativeItemTime(Number.NaN, 1_000)).toBe("unknown");
  });
});
