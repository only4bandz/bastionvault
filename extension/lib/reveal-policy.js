// REVEAL field policy.
//
// The REVEAL verb is the popup's generic "read one secret field" accessor.
// Left unconstrained, `item[msg.field]` reads ANY property — including
// prototype-chain names (`__proto__`, `constructor`) and whatever internal
// fields future item shapes carry. Every other router verb is deliberately
// narrow; this allowlist makes REVEAL match that discipline.

const REVEALABLE = new Set(["password", "cardNumber", "cardCvv", "cardExp", "notes", "username"]);

/** `true` when the popup may read this item field through REVEAL. */
export function isRevealableField(field) {
  return typeof field === "string" && REVEALABLE.has(field);
}

/** The field value, own-properties only — never the prototype chain. */
export function revealFieldValue(item, field) {
  if (!isRevealableField(field)) throw new Error("Field not revealable.");
  return item && Object.hasOwn(item, field) ? item[field] || "" : "";
}
