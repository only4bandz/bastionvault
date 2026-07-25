import { describe, expect, it } from "vitest";
import type { VaultItem } from "./types";
import {
  analyzePasswordHealth,
  assessPassword,
  identityDerivedToken,
  passwordStem,
  riskLabels,
} from "./password-health";

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

describe("identityDerivedToken", () => {
  const entry = (fields: Partial<VaultItem>): VaultItem => ({
    id: "x",
    type: "login",
    title: "Acme Bank",
    updatedAt: 1,
    ...fields,
  });

  it.each([
    [
      "email local part",
      { username: "ada.lovelace@example.com", password: "AdaLovelace-9x!" },
      "ada.lovelace",
      "username",
    ],
    ["site label", { url: "https://login.github.com/x", password: "gitHub-2024!" }, "github", "website"],
    ["title word", { password: "acme-Tr0ub4dor" }, "Acme", "title"],
    ["l33t spelling", { username: "octocat", password: "0ct0c4t-Rides!" }, "octocat", "username"],
  ])("flags a password derived from the %s", (_name, fields, token, source) => {
    expect(identityDerivedToken(entry(fields))).toEqual({ token, source });
  });

  it("reports the longest match so the most specific fragment is named", () => {
    // "acme" (title word) and "acmebank" (title) both match.
    expect(identityDerivedToken(entry({ title: "acmebank", password: "acmebank-9xQ!" }))).toEqual({
      token: "acmebank",
      source: "title",
    });
  });

  it.each([
    ["no password", { password: undefined }],
    ["unrelated password", { username: "ada@example.com", password: "V7!kQ2#pL9@xR4$m" }],
    ["fragment shorter than four characters", { title: "Bob", password: "bob-V7!kQ2#pL9@x" }],
    ["generic host label only", { title: "Site", url: "https://www.com", password: "www-V7!kQ2#pL9@" }],
  ])("returns null for %s", (_name, fields) => {
    expect(identityDerivedToken(entry(fields))).toBeNull();
  });
});

describe("passwordStem", () => {
  it.each([
    ["Hunter2", "hunter"],
    ["  hunter3!  ", "hunter"],
    ["HUNTER_2024", "hunter"],
    ["Xq7!vP2zRt", "xq7!vp2zrt"],
  ])("reduces %s to its stem", (password, stem) => {
    expect(passwordStem(password)).toBe(stem);
  });

  it.each(["1234", "ab1!", "!!!!!!"])("returns null for %s, which has no usable stem", (password) => {
    expect(passwordStem(password)).toBeNull();
  });
});

describe("analyzePasswordHealth", () => {
  it("groups near-identical passwords that exact-match reuse cannot see", () => {
    const analysis = analyzePasswordHealth([
      login("a", "Alpha", "Xq7vPzRtKm1"),
      login("b", "Beta", "xq7vpzrtkm2!"),
      login("c", "Charlie", "N8@vT3!sW6#qY2%h"),
    ]);

    expect(analysis.reusedGroups).toEqual([]); // no two passwords are equal
    expect(analysis.variantGroups).toHaveLength(1);
    expect(analysis.variantGroups[0].items.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.variantItems.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.atRiskItems.map((item) => item.id)).toEqual(["a", "b"]);
    expect(analysis.score).toBe(33);
  });

  it("does not double-report exact reuse as a variant group", () => {
    const shared = "Xq7vPzRtKm1";
    const analysis = analyzePasswordHealth([login("a", "Alpha", shared), login("b", "Beta", shared)]);

    expect(analysis.reusedGroups).toHaveLength(1);
    expect(analysis.variantGroups).toEqual([]);
    expect(analysis.variantItems).toEqual([]);
  });

  it("keeps unrelated strong passwords out of variant groups", () => {
    const analysis = analyzePasswordHealth([
      login("a", "Alpha", "V7!kQ2#pL9@xR4$m"),
      login("b", "Beta", "N8@vT3!sW6#qY2%h"),
    ]);

    expect(analysis.variantGroups).toEqual([]);
    expect(analysis.score).toBe(100);
  });

  it("counts a self-derived password as at risk even when it is strong and unique", () => {
    const item: VaultItem = {
      id: "gh",
      type: "login",
      title: "GitHub",
      username: "octocat",
      password: "github-Xq7!vP2z",
      updatedAt: 1,
    };
    const analysis = analyzePasswordHealth([item]);

    expect(analysis.weakItems).toEqual([]);
    expect(analysis.reusedItems).toEqual([]);
    expect(analysis.identityItems).toEqual([{ item, token: "GitHub", source: "title" }]);
    expect(analysis.atRiskItems.map((entry) => entry.id)).toEqual(["gh"]);
    expect(analysis.score).toBe(0);
  });

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

describe("password age", () => {
  const DAY = 24 * 60 * 60 * 1000;
  const NOW = 1_800_000_000_000;

  it("flags passwords unchanged for more than a year", () => {
    const fresh = { ...login("fresh", "Fresh", "V7!kQ2#pL9@xR4$m"), passwordChangedAt: NOW - 30 * DAY };
    const stale = { ...login("stale", "Stale", "W8!mR3#qN0@yS5$n"), passwordChangedAt: NOW - 400 * DAY };
    const analysis = analyzePasswordHealth([fresh, stale], NOW);
    expect(analysis.oldItems.map((i) => i.id)).toEqual(["stale"]);
    expect(analysis.atRiskItems.map((i) => i.id)).toContain("stale");
    expect(analysis.score).toBe(50);
  });

  it("falls back to updatedAt when passwordChangedAt is absent", () => {
    const legacy = { ...login("legacy", "Legacy", "V7!kQ2#pL9@xR4$m"), updatedAt: NOW - 366 * DAY };
    const analysis = analyzePasswordHealth([legacy], NOW);
    expect(analysis.oldItems.map((i) => i.id)).toEqual(["legacy"]);
  });

  it("skips age analysis entirely when no clock is provided", () => {
    const stale = { ...login("stale", "Stale", "W8!mR3#qN0@yS5$n"), passwordChangedAt: 1 };
    const analysis = analyzePasswordHealth([stale]);
    expect(analysis.oldItems).toEqual([]);
    expect(analysis.score).toBe(100);
  });
});

describe("expanded common-password detection", () => {
  it.each(["Sunshine12!", "Football99!", "Princess2024", "Tru5tno1!", "Starwars#1"])(
    "caps breach-corpus leader %s as weak",
    (password) => {
      const assessment = assessPassword(password);
      expect(assessment.score).toBeLessThanOrEqual(1);
      expect(assessment.reasons).toContain("Common password pattern");
    }
  );

  it("caps any word followed by a year, even outside the common list", () => {
    const assessment = assessPassword("Maple2023!");
    expect(assessment.score).toBeLessThanOrEqual(2);
    expect(assessment.reasons).toContain("Word with a year suffix");
  });

  it("does not flag genuinely random values", () => {
    expect(assessPassword("V7!kQ2#pL9@xR4$m").reasons).toEqual([
      "No obvious offline pattern detected",
    ]);
  });
});

describe("keyboard-walk detection", () => {
  it.each([
    "1qaz2wsx",
    "1QAZ2wsx!",
    "zaq1xsw2",
    "qazwsxedc",
    "Tr0ubadour1qaz2wsx",
    "xsw2zaq1",
  ])("caps keyboard walk %s as weak", (password) => {
    const assessment = assessPassword(password);
    expect(assessment.score).toBeLessThanOrEqual(1);
    expect(assessment.reasons).toContain("Keyboard pattern");
  });

  it.each(["V7!kQ2#pL9@xR4$m", "N8@vT3!sW6#qY2%h", "correct-horse-battery"])(
    "leaves %s unflagged",
    (password) => {
      expect(assessPassword(password).reasons).not.toContain("Keyboard pattern");
    }
  );

  it("reports a straight row run as a sequence, not a duplicate keyboard finding", () => {
    const assessment = assessPassword("qwertyui");
    expect(assessment.reasons).toContain("Predictable sequence");
    expect(assessment.reasons).not.toContain("Keyboard pattern");
  });
});

describe("riskLabels", () => {
  const NOW = 1_800_000_000_000;
  const YEAR = 366 * 24 * 60 * 60 * 1000;

  it("labels each finding and reports the most severe one per item", () => {
    const items: VaultItem[] = [
      // Weak *and* reused: weak wins, it is cheaper to exploit.
      login("weak-a", "Alpha", "P@ssw0rd123!"),
      login("weak-b", "Beta", "P@ssw0rd123!"),
      // Reused but strong.
      login("reused-a", "Charlie", "V7!kQ2#pL9@xR4$m"),
      login("reused-b", "Delta", "V7!kQ2#pL9@xR4$m"),
      // Near-identical pair.
      login("variant-a", "Echo", "Xq7vPzRtKm1"),
      login("variant-b", "Foxtrot", "xq7vpzrtkm2!"),
      // Strong, unique, but built from the title.
      login("identity", "Zanzibar", "zanzibar-Nq8!vT3z"),
      // Strong, unique, unrelated — only old.
      { ...login("old", "Golf", "N8@vT3!sW6#qY2%h"), passwordChangedAt: NOW - YEAR },
      // Clean.
      { ...login("clean", "Hotel", "W4#nR8!zK2@yD6%b"), passwordChangedAt: NOW },
    ];
    const labels = riskLabels(analyzePasswordHealth(items, NOW));

    expect(Object.fromEntries(labels)).toEqual({
      "weak-a": "Weak",
      "weak-b": "Weak",
      "reused-a": "Reused",
      "reused-b": "Reused",
      "variant-a": "Near-identical",
      "variant-b": "Near-identical",
      identity: "Self-derived",
      old: "Old",
    });
    expect(labels.has("clean")).toBe(false);
  });

  it("is empty for a healthy vault", () => {
    const fresh = { ...login("a", "Alpha", "V7!kQ2#pL9@xR4$m"), passwordChangedAt: NOW };
    const analysis = analyzePasswordHealth([fresh], NOW);
    expect(riskLabels(analysis).size).toBe(0);
  });
});
