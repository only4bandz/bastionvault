import { describe, expect, it } from "vitest";
import {
  MAX_GENERATED_PASSWORD_LENGTH,
  generatePassword,
  uniformRandomInt,
  type GenOptions,
} from "./generator";

const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/";
const UINT32_MAX = 0xffff_ffff;
const BASE: GenOptions = {
  length: 32,
  lower: false,
  upper: false,
  digits: false,
  symbols: false,
  avoidAmbiguous: false,
};

const combinations = Array.from({ length: 15 }, (_, mask) => ({
  ...BASE,
  lower: Boolean((mask + 1) & 1),
  upper: Boolean((mask + 1) & 2),
  digits: Boolean((mask + 1) & 4),
  symbols: Boolean((mask + 1) & 8),
}));

describe("generatePassword", () => {
  it.each(combinations)("guarantees every enabled class for %#", (options) => {
    for (let sample = 0; sample < 64; sample++) {
      const password = generatePassword(options);
      expect(password).toHaveLength(options.length);
      expect(/[a-z]/.test(password)).toBe(options.lower);
      expect(/[A-Z]/.test(password)).toBe(options.upper);
      expect(/[0-9]/.test(password)).toBe(options.digits);
      expect([...password].some((character) => SYMBOLS.includes(character))).toBe(
        options.symbols
      );
    }
  });

  it("excludes ambiguous characters when requested", () => {
    const options: GenOptions = {
      ...BASE,
      lower: true,
      upper: true,
      digits: true,
      symbols: true,
      avoidAmbiguous: true,
      length: 64,
    };
    for (let sample = 0; sample < 128; sample++) {
      expect(generatePassword(options)).not.toMatch(/[01lIO]/);
    }
  });

  it("rejects lengths that cannot satisfy the enabled classes or exceed the bound", () => {
    expect(() =>
      generatePassword({ ...BASE, lower: true, upper: true, digits: true, length: 2 })
    ).toThrow("Password length must be an integer from 3 to 256.");
    expect(() =>
      generatePassword({ ...BASE, lower: true, length: MAX_GENERATED_PASSWORD_LENGTH + 1 })
    ).toThrow("Password length must be an integer from 1 to 256.");
    expect(generatePassword(BASE)).toBe("");
  });
});

describe("uniformRandomInt", () => {
  it("rejects the incomplete tail of the uint32 range before applying modulo", () => {
    const values = [0xffff_ffff, 52];
    let calls = 0;
    const result = uniformRandomInt(26, (buffer) => {
      buffer[0] = values[calls++];
    });

    expect(result).toBe(0);
    expect(calls).toBe(2);
  });

  it.each([0, -1, 1.5, Number.NaN, UINT32_MAX + 2])(
    "rejects invalid bound %s",
    (bound) => {
      expect(() => uniformRandomInt(bound)).toThrow(RangeError);
    }
  );
});
