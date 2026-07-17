import { describe, expect, it } from "vitest";
import {
  MAX_CSV_COLUMNS,
  MAX_CSV_FIELD_CHARS,
  MAX_IMPORT_ITEMS,
  CsvImportError,
  csvToItems,
  parseCsv,
} from "./import";

describe("parseCsv", () => {
  it("preserves quoted commas, newlines, escaped quotes, and CR-only rows", () => {
    expect(parseCsv('name,password\r"GitHub, Inc","line 1\nline ""2"""')).toEqual([
      ["name", "password"],
      ["GitHub, Inc", 'line 1\nline "2"'],
    ]);
  });

  it("rejects malformed quoted fields", () => {
    expect(() => parseCsv('name,password\nGitHub,"unterminated')).toThrow(
      "The CSV ends inside a quoted field."
    );
    expect(() => parseCsv('name,password\nGit"Hub,secret')).toThrow(
      "A quoted CSV field must start immediately after a delimiter."
    );
    expect(() => parseCsv('name,password\n"GitHub"unexpected,secret')).toThrow(
      "Unexpected content after a quoted CSV field."
    );
  });

  it("enforces row, column, and field bounds while parsing", () => {
    const tooManyRows = `name\n${"item\n".repeat(MAX_IMPORT_ITEMS + 1)}`;
    expect(() => parseCsv(tooManyRows)).toThrow(
      `CSV files cannot contain more than ${MAX_IMPORT_ITEMS} data rows.`
    );

    const tooManyColumns = Array.from(
      { length: MAX_CSV_COLUMNS + 1 },
      (_, index) => `column-${index}`
    ).join(",");
    expect(() => parseCsv(tooManyColumns)).toThrow(
      `CSV rows cannot contain more than ${MAX_CSV_COLUMNS} columns.`
    );

    expect(() => parseCsv(`name\n${"x".repeat(MAX_CSV_FIELD_CHARS + 1)}`)).toThrow(
      "A CSV field exceeds the 128 Ki character limit."
    );
  });
});

describe("csvToItems", () => {
  it("maps supported item types and preserves password whitespace verbatim", () => {
    const result = csvToItems(
      '\uFEFFname,type,url,username,password,notes,cardnumber,expiry,cvc\n' +
        'GitHub,login,https://github.com,general,  password with spaces  ,note,,,\n' +
        'Operations card,card,,,,,4111111111111111,12/29,123\n' +
        ',note,,,,classified,,,'
    );

    expect(result.skipped).toBe(1);
    expect(result.items).toHaveLength(2);
    expect(result.items[0]).toMatchObject({
      type: "login",
      title: "GitHub",
      password: "  password with spaces  ",
    });
    expect(result.items[1]).toMatchObject({
      type: "card",
      cardNumber: "4111111111111111",
      cardExp: "12/29",
      cardCvv: "123",
    });
  });

  it("requires an explicit name or title header", () => {
    expect(() => csvToItems("")).toThrow("CSV must include a header row.");
    expect(csvToItems("name,password")).toEqual({ items: [], skipped: 0 });
    expect(() => csvToItems("username,password\ngeneral,secret")).toThrow(
      'CSV header must include a "name" or "title" column.'
    );
  });

  it("preserves an imported cardholder name", () => {
    const result = csvToItems(
      "name,type,cardholdername,cardnumber\nOperations card,card,General Example,4111111111111111"
    );
    expect(result.items[0]).toMatchObject({
      type: "card",
      cardholderName: "General Example",
      cardNumber: "4111111111111111",
    });
  });

  it("imports strict Bastion dashboard metadata", () => {
    const result = csvToItems(
      "name,type,favorite,updatedat,passwordchangedat,cardbrand,cardbank,cardbankdomain,cardtype,cardnumber\n" +
        "Operations card,card,true,1700000000000,1600000000000,visa,Example Bank,bank.example,credit,4111111111111111"
    );
    expect(result.items[0]).toMatchObject({
      favorite: true,
      updatedAt: 1_700_000_000_000,
      passwordChangedAt: 1_600_000_000_000,
      cardBrand: "visa",
      cardBank: "Example Bank",
      cardBankDomain: "bank.example",
      cardType: "credit",
    });
  });

  it.each([
    ["favorite", "yes"],
    ["updatedat", "-1"],
    ["passwordchangedat", "not-a-number"],
  ])("rejects invalid %s metadata", (header, value) => {
    expect(() => csvToItems(`name,${header}\nGitHub,${value}`)).toThrow(CsvImportError);
  });

  it("rejects an item whose UTF-8 payload exceeds the encrypted-item envelope", () => {
    const oversizedUtf8Title = "😀".repeat(65_536);
    expect(() => csvToItems(`name\n${oversizedUtf8Title}`)).toThrow(CsvImportError);
    expect(() => csvToItems(`name\n${oversizedUtf8Title}`)).toThrow(
      "CSV row 2 exceeds the 256 KiB item limit."
    );
  });
});
