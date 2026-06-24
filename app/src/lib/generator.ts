// Password generator using the browser CSPRNG (crypto.getRandomValues).
export interface GenOptions {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

const LOWER = "abcdefghijkmnopqrstuvwxyz";
const LOWER_AMB = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";
const UPPER_AMB = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS = "23456789";
const DIGITS_AMB = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";

function randInt(max: number): number {
  // Rejection sampling for a uniform value in [0, max).
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let x = 0;
  do {
    crypto.getRandomValues(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

export function generatePassword(o: GenOptions): string {
  let pool = "";
  if (o.lower) pool += o.avoidAmbiguous ? LOWER : LOWER_AMB;
  if (o.upper) pool += o.avoidAmbiguous ? UPPER : UPPER_AMB;
  if (o.digits) pool += o.avoidAmbiguous ? DIGITS : DIGITS_AMB;
  if (o.symbols) pool += SYMBOLS;
  if (!pool) return "";
  let out = "";
  for (let i = 0; i < o.length; i++) out += pool[randInt(pool.length)];
  return out;
}

/** Rough strength score 0..4 for a password. */
export function strength(pw: string): { score: number; label: string; color: string } {
  if (!pw) return { score: 0, label: "—", color: "#232b3b" };
  let classes = 0;
  if (/[a-z]/.test(pw)) classes++;
  if (/[A-Z]/.test(pw)) classes++;
  if (/[0-9]/.test(pw)) classes++;
  if (/[^a-zA-Z0-9]/.test(pw)) classes++;
  const entropy = pw.length * classes;
  let score = 1;
  if (entropy >= 28) score = 2;
  if (entropy >= 48) score = 3;
  if (entropy >= 80) score = 4;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  const colors = ["#ff5d6c", "#ff5d6c", "#ffb454", "#3ad29f", "#3ad29f"];
  return { score, label: labels[score], color: colors[score] };
}
