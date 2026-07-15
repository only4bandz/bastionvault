import { describe, expect, it } from "vitest";
import type { VaultItem } from "./types";
import { analyzePasswordHealth, assessPassword } from "./password-health";

const login = (id: string, title: string, password?: string): VaultItem => ({
  id,
  type: "login",
  title,
  password,
  updatedAt: 1,
});

describe("assessPassword", () => {
  it.each(["aaaaaaaaaaaaaaaa", "abcabcabcabc", "abcdefghijklmnop", "P@ssw0rd123!"])(
    "caps obvious offline pattern %s as weak",
    (password) => {
      expect(assessPassword(password).score).toBeLessThan(2);
    }
  );

  it("recognizes long mixed random-looking values without external lookups", () => {
    expect(assessPassword("V7!kQ2#pL9@xR4$m")).toMatchObject({
      score: 4,
      label: "Excellent",
      reasons: ["No obvious offline pattern detected"],
    });
  });
});

describe("analyzePasswordHealth", () => {
  it("returns no score when there are no passwords to assess", () => {
    const analysis = analyzePasswordHealth([
      login("empty", "No stored password"),
      { id: "note", type: "note", title: "Note", notes: "secret", updatedAt: 1 },
    ]);

    expect(analysis.score).toBeNull();
    expect(analysis.loginCount).toBe(1);
    expect(analysis.assessedCount).toBe(0);
    expect(analysis.atRiskItems).toEqual([]);
  });

  it("groups exact reuse and counts weak-and-reused items only once", () => {
    const weakAndReused = "P@ssw0rd123!";
    const analysis = analyzePasswordHealth([
      login("b", "Beta", weakAndReused),
      login("a", "Alpha", weakAndReused),
      login("c", "Charlie", "V7!kQ2#pL9@xR4$m"),
    ]);

    expect(analysis.weakItems.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.reusedGroups).toHaveLength(1);
    expect(analysis.reusedGroups[0].items.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.reusedItems.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.atRiskItems.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.score).toBe(33);
  });

  it("scores a vault with unique strong passwords at 100 without mutating input order", () => {
    const items = [
      login("z", "Zulu", "V7!kQ2#pL9@xR4$m"),
      login("a", "Alpha", "N8@vT3!sW6#qY2%h"),
    ];
    const originalOrder = items.map((item) => item.id);
    const analysis = analyzePasswordHealth(items);

    expect(analysis.score).toBe(100);
    expect(analysis.weakItems).toEqual([]);
    expect(analysis.reusedGroups).toEqual([]);
    expect(items.map((item) => item.id)).toEqual(originalOrder);
  });
});
