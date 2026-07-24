// Spreadsheet formula-injection guard for CSV export/import.
//
// Cells beginning with = + - @ (or a tab/CR remnant) are interpreted as
// formulas by Excel, LibreOffice and Google Sheets, turning an exported
// vault into a code-execution vector the moment it is opened for review
// (e.g. a stored password of `=cmd|' /C calc'!A0`). OWASP's mitigation is
// a leading apostrophe, which spreadsheets treat as "literal text" and do
// not display. Import strips exactly the prefix export adds, so a
// Bastion-exported file round-trips losslessly.
const DANGEROUS_LEAD = /^[=+\-@\t\r]/;

/** Export side: neutralize a would-be formula with a literal-text apostrophe. */
export function escapeFormulaPrefix(value: string): string {
  return DANGEROUS_LEAD.test(value) ? `'${value}` : value;
}

/**
 * Import side: undo escapeFormulaPrefix. Only an apostrophe immediately
 * followed by a formula-leading character is removed — apostrophes that are
 * genuinely part of the value are untouched.
 */
export function stripFormulaPrefix(value: string): string {
  return value.startsWith("'") && DANGEROUS_LEAD.test(value.slice(1)) ? value.slice(1) : value;
}
