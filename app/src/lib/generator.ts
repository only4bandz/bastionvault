// Password generator using the browser CSPRNG (crypto.getRandomValues).
import { assessPassword } from "./password-health";

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
const UINT32_RANGE = 0x1_0000_0000;
export const MAX_GENERATED_PASSWORD_LENGTH = 256;

export function uniformRandomInt(
  max: number,
  fillRandom: (buffer: Uint32Array<ArrayBuffer>) => void = (buffer) => {
    crypto.getRandomValues(buffer);
  }
): number {
  if (!Number.isSafeInteger(max) || max < 1 || max > UINT32_RANGE) {
    throw new RangeError("Random upper bound must be an integer between 1 and 2^32.");
  }
  // Rejection sampling for a uniform value in [0, max).
  const limit = Math.floor(UINT32_RANGE / max) * max;
  const buf = new Uint32Array(new ArrayBuffer(Uint32Array.BYTES_PER_ELEMENT));
  let x = 0;
  do {
    fillRandom(buf);
    x = buf[0];
  } while (x >= limit);
  return x % max;
}

export function generatePassword(o: GenOptions): string {
  const classes = [
    o.lower ? (o.avoidAmbiguous ? LOWER : LOWER_AMB) : "",
    o.upper ? (o.avoidAmbiguous ? UPPER : UPPER_AMB) : "",
    o.digits ? (o.avoidAmbiguous ? DIGITS : DIGITS_AMB) : "",
    o.symbols ? SYMBOLS : "",
  ].filter(Boolean);
  if (classes.length === 0) return "";
  if (
    !Number.isSafeInteger(o.length) ||
    o.length < classes.length ||
    o.length > MAX_GENERATED_PASSWORD_LENGTH
  ) {
    throw new RangeError(
      `Password length must be an integer from ${classes.length} to ${MAX_GENERATED_PASSWORD_LENGTH}.`
    );
  }

  const pool = classes.join("");
  const output = classes.map((characters) =>
    characters[uniformRandomInt(characters.length)]
  );
  while (output.length < o.length) {
    output.push(pool[uniformRandomInt(pool.length)]);
  }

  // Fisher-Yates prevents the guaranteed class characters from occupying
  // predictable leading positions.
  for (let index = output.length - 1; index > 0; index--) {
    const swapWith = uniformRandomInt(index + 1);
    [output[index], output[swapWith]] = [output[swapWith], output[index]];
  }
  return output.join("");
}

/** Offline deterministic strength score 0..4 for a password. */
export function strength(pw: string): { score: number; label: string; color: string } {
  const { score, label, color } = assessPassword(pw);
  return { score, label, color };
}
