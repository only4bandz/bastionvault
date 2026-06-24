// Password generator (ESM, for the popup). Uses the browser CSPRNG with
// rejection sampling so each character is unbiased. content.js carries its own
// inline copy because content scripts can't import ES modules.

const SETS = {
  lower: "abcdefghijkmnpqrstuvwxyz", // no l
  upper: "ABCDEFGHJKLMNPQRSTUVWXYZ", // no I, O
  digits: "23456789", // no 0, 1 (ambiguity)
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};

function randInt(n) {
  const max = Math.floor(0xffffffff / n) * n; // reject the biased tail
  const buf = new Uint32Array(1);
  let x;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= max);
  return x % n;
}

function shuffle(a) {
  for (let i = a.length - 1; i > 0; i--) {
    const j = randInt(i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
}

/** Generate a password. Guarantees ≥1 char from each enabled set. */
export function generatePassword(opts = {}) {
  const { length = 20, lower = true, upper = true, digits = true, symbols = true } = opts;
  const enabled = [];
  if (lower) enabled.push(SETS.lower);
  if (upper) enabled.push(SETS.upper);
  if (digits) enabled.push(SETS.digits);
  if (symbols) enabled.push(SETS.symbols);
  if (!enabled.length) enabled.push(SETS.lower);

  const pool = enabled.join("");
  const len = Math.max(8, Math.min(length, 64));
  const chars = enabled.map((set) => set[randInt(set.length)]); // one of each
  while (chars.length < len) chars.push(pool[randInt(pool.length)]);
  shuffle(chars);
  return chars.slice(0, len).join("");
}
