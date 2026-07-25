import type { VaultItem } from "./types";

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
const COLORS = ["#ff5d6c", "#ff5d6c", "#ffb454", "#3ad29f", "#3ad29f"];
// Top common-password tokens (offline, deterministic — matched against the
// l33t-normalized password). Sourced from the recurring leaders of breach
// corpora (rockyou / SecLists top lists), lowercased, deduplicated.
const COMMON_TOKENS = [
  "password", "letmein", "qwerty", "welcome", "admin", "iloveyou", "monkey",
  "dragon", "sunshine", "princess", "football", "baseball", "basketball", "soccer",
  "hockey", "superman", "batman", "master", "shadow", "michael", "jennifer",
  "jordan", "hunter", "harley", "ranger", "buster", "thomas", "robert",
  "killer", "george", "andrew", "charlie", "daniel", "ashley", "jessica",
  "amanda", "nicole", "chelsea", "biteme", "matrix", "secret", "freedom",
  "whatever", "trustno", "starwars", "computer", "corvette", "mercedes", "ferrari",
  "cheese", "pepper", "ginger", "banana", "orange", "purple", "yellow",
  "silver", "golden", "cookie", "summer", "winter", "spring", "autumn",
  "flower", "butterfly", "rainbow", "diamond", "tigger", "snoopy", "mickey",
  "pokemon", "pikachu", "naruto", "gandalf", "hannah", "maggie", "sophie",
  "pandora", "phoenix", "scorpio", "taurus", "gemini", "peanut", "cowboy",
  "eagles", "yankees", "lakers", "dallas", "chicago", "london", "austin",
  "canada", "america", "mexico", "money", "loveme", "lovely", "angels",
  "bailey", "access", "please", "internet", "samsung", "google", "gaming",
  "soccer1", "abc123", "test",
] as const;
const SEQUENCES = [
  "0123456789",
  "9876543210",
  "abcdefghijklmnopqrstuvwxyz",
  "zyxwvutsrqponmlkjihgfedcba",
  "qwertyuiopasdfghjklzxcvbnm",
  "mnbvcxzlkjhgfdsaqpoiuytrewq",
];

export interface PasswordAssessment {
  score: number;
  label: string;
  color: string;
  reasons: string[];
}

export interface ReusedPasswordGroup {
  items: VaultItem[];
}

/** An item whose own password is derived from its own visible identity. */
export interface IdentityDerivedFinding {
  item: VaultItem;
  /** The identity token found inside the password, as stored (not normalized). */
  token: string;
  /** Where that token came from, for the UI to name it. */
  source: "username" | "website" | "title";
}

/**
 * Shortest identity fragment worth matching. Below this, hits are noise —
 * "bob" appears inside plenty of unrelated strings, and a three-character
 * word contributes almost nothing to a guess list anyway.
 */
const MIN_IDENTITY_TOKEN = 4;

/** Registrable-looking labels that identify nothing about a specific site. */
const GENERIC_HOST_LABELS = new Set(["www", "com", "net", "org", "co", "login", "auth", "account"]);

function identityTokens(item: VaultItem): { token: string; source: IdentityDerivedFinding["source"] }[] {
  const tokens: { token: string; source: IdentityDerivedFinding["source"] }[] = [];
  const push = (raw: string | undefined, source: IdentityDerivedFinding["source"]): void => {
    const token = (raw ?? "").trim();
    if (token) tokens.push({ token, source });
  };

  // Username: the whole value and, for an email, the local part on its own —
  // "ada@example.com" makes both "ada@example.com" and "ada" worth checking.
  push(item.username, "username");
  const at = (item.username ?? "").indexOf("@");
  if (at > 0) push(item.username!.slice(0, at), "username");

  // Website: each hostname label except the generic ones, so
  // "https://login.github.com/x" contributes "github".
  const host = (() => {
    try {
      return new URL(item.url!).hostname;
    } catch {
      return "";
    }
  })();
  for (const label of host.split(".")) {
    if (!GENERIC_HOST_LABELS.has(label.toLowerCase())) push(label, "website");
  }

  // Title: the whole thing plus each word, so "Acme Bank" yields "acme".
  push(item.title, "title");
  for (const word of item.title.split(/\s+/)) push(word, "title");

  return tokens;
}

/**
 * Report the identity fragment a password is built from, if any.
 *
 * "github2024", "AdaAda!" and "acmebank1" survive every generic strength check
 * — they are long enough, mixed enough, and match no common-password list —
 * yet they are the first candidates any targeted attacker tries, because the
 * vault entry itself hands over the base word. This check is per-item and
 * needs no wordlist: the item's own username, website and title are the list.
 *
 * The longest matching token wins, so a hit is reported against the most
 * specific fragment rather than an incidental short one.
 */
export function identityDerivedToken(
  item: VaultItem
): Omit<IdentityDerivedFinding, "item"> | null {
  const password = item.password;
  if (!password) return null;
  const normalizedPassword = normalizeCommonPatterns(password);
  if (!normalizedPassword) return null;

  let best: Omit<IdentityDerivedFinding, "item"> | null = null;
  for (const { token, source } of identityTokens(item)) {
    const normalizedToken = normalizeCommonPatterns(token);
    if (normalizedToken.length < MIN_IDENTITY_TOKEN) continue;
    if (!normalizedPassword.includes(normalizedToken)) continue;
    if (best === null || normalizedToken.length > normalizeCommonPatterns(best.token).length) {
      best = { token, source };
    }
  }
  return best;
}

export interface PasswordHealthAnalysis {
  score: number | null;
  loginCount: number;
  assessedCount: number;
  weakItems: VaultItem[];
  reusedItems: VaultItem[];
  reusedGroups: ReusedPasswordGroup[];
  identityItems: IdentityDerivedFinding[];
  oldItems: VaultItem[];
  atRiskItems: VaultItem[];
  assessments: ReadonlyMap<string, PasswordAssessment>;
}

/** A password unchanged for longer than this is flagged as old. */
export const PASSWORD_AGE_LIMIT_MS = 365 * 24 * 60 * 60 * 1000;

/** Age reference for an item: explicit password timestamp, else last edit. */
export function passwordAgeReference(item: VaultItem): number {
  return item.passwordChangedAt ?? item.updatedAt;
}

function normalizeCommonPatterns(password: string): string {
  return password
    .toLowerCase()
    .replace(/[@4]/g, "a")
    .replace(/[!1]/g, "i")
    .replace(/3/g, "e")
    .replace(/[$5]/g, "s")
    .replace(/0/g, "o")
    .replace(/7/g, "t")
    .replace(/[^a-z0-9]/g, "");
}

function isRepeatedPattern(value: string): boolean {
  for (let size = 1; size <= Math.floor(value.length / 2); size++) {
    if (value.length % size === 0 && value.slice(0, size).repeat(value.length / size) === value) {
      return true;
    }
  }
  return false;
}

export function assessPassword(password: string): PasswordAssessment {
  if (!password) {
    return { score: 0, label: "—", color: "#232b3b", reasons: ["No password"] };
  }

  let poolSize = 0;
  let classCount = 0;
  if (/[a-z]/.test(password)) { poolSize += 26; classCount++; }
  if (/[A-Z]/.test(password)) { poolSize += 26; classCount++; }
  if (/[0-9]/.test(password)) { poolSize += 10; classCount++; }
  if (/[^a-zA-Z0-9]/.test(password)) { poolSize += 33; classCount++; }

  const estimatedBits = password.length * Math.log2(Math.max(poolSize, 1));
  let score =
    password.length < 8 ? 0 : estimatedBits < 36 ? 1 : estimatedBits < 60 ? 2 : estimatedBits < 80 ? 3 : 4;
  const reasons: string[] = [];
  const normalized = normalizeCommonPatterns(password);
  const repeated = password.length >= 4 && isRepeatedPattern(password.toLowerCase());
  const sequence =
    normalized.length >= 4 && SEQUENCES.some((candidate) => candidate.includes(normalized));
  const common = COMMON_TOKENS.some((token) => normalized.includes(token));

  if (/^(.)\1+$/.test(password)) {
    score = 0;
    reasons.push("Single repeated character");
  } else if (repeated) {
    score = Math.min(score, 1);
    reasons.push("Repeated pattern");
  }
  if (sequence) {
    score = Math.min(score, 1);
    reasons.push("Predictable sequence");
  }
  if (common) {
    score = Math.min(score, 1);
    reasons.push("Common password pattern");
  }
  // "Maple2023!"-style: any single word followed by a plausible year. The
  // base word need not be in the common list — the *shape* alone is one of
  // the first patterns offline crackers enumerate.
  if (
    !common &&
    /^[a-z]{3,}(19|20)\d{2}$/.test(password.toLowerCase().replace(/[^a-z0-9]/g, ""))
  ) {
    score = Math.min(score, 2);
    reasons.push("Word with a year suffix");
  }
  if (password.length < 12) reasons.push("Fewer than 12 characters");
  if (classCount < 2) reasons.push("Uses only one character class");
  if (reasons.length === 0) reasons.push("No obvious offline pattern detected");

  return { score, label: LABELS[score], color: COLORS[score], reasons };
}

function compareItems(left: VaultItem, right: VaultItem): number {
  const leftKey = `${left.title}\u0000${left.id}`;
  const rightKey = `${right.title}\u0000${right.id}`;
  return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
}

/**
 * `now` is injected (not read from the clock) so the analysis stays
 * deterministic — pass `Date.now()` from the UI, a fixed instant in tests.
 */
export function analyzePasswordHealth(items: VaultItem[], now?: number): PasswordHealthAnalysis {
  const loginCount = items.filter((item) => item.type === "login").length;
  const assessed = items
    .filter((item) => item.type === "login" && Boolean(item.password))
    .slice()
    .sort(compareItems);
  const assessments = new Map<string, PasswordAssessment>();
  const byPassword = new Map<string, VaultItem[]>();

  assessed.forEach((item) => {
    assessments.set(item.id, assessPassword(item.password!));
    const matches = byPassword.get(item.password!) ?? [];
    matches.push(item);
    byPassword.set(item.password!, matches);
  });

  const weakItems = assessed.filter((item) => assessments.get(item.id)!.score < 2);
  const reusedGroups = [...byPassword.values()]
    .filter((group) => group.length > 1)
    .map((group) => ({ items: group.slice().sort(compareItems) }))
    .sort((left, right) => compareItems(left.items[0], right.items[0]));
  const reusedIds = new Set(reusedGroups.flatMap((group) => group.items.map((item) => item.id)));
  const reusedItems = assessed.filter((item) => reusedIds.has(item.id));
  const identityItems = assessed.flatMap((item) => {
    const finding = identityDerivedToken(item);
    return finding ? [{ item, ...finding }] : [];
  });
  const oldItems =
    now === undefined
      ? []
      : assessed.filter((item) => now - passwordAgeReference(item) > PASSWORD_AGE_LIMIT_MS);
  const atRiskIds = new Set(
    [...weakItems, ...reusedItems, ...identityItems.map((finding) => finding.item), ...oldItems].map(
      (item) => item.id
    )
  );
  const atRiskItems = assessed.filter((item) => atRiskIds.has(item.id));
  const score =
    assessed.length === 0
      ? null
      : Math.round(100 * (1 - atRiskItems.length / assessed.length));

  return {
    score,
    loginCount,
    assessedCount: assessed.length,
    weakItems,
    reusedItems,
    reusedGroups,
    identityItems,
    oldItems,
    atRiskItems,
    assessments,
  };
}
