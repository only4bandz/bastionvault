// Redaction of decrypted items handed to the popup.
//
// The popup is a trusted extension page, but "trusted" is not a reason to
// hand it every secret an item holds. The detail view needs to *render* an
// item; it needs a secret's plaintext only at the moment the user reveals or
// copies that one field — which is exactly what the REVEAL verb is for.
// Shipping the whole item put passwords, card numbers and CVVs into the
// popup's DOM (and its JS heap) for the entire lifetime of the view.
//
// So ITEM returns everything needed to draw the view and nothing that needs
// to stay secret: masks are sized from a length, and health is computed
// before redaction.

import { passwordStrength } from "./password-strength.js";

/** Item fields that must never travel unless the user asked for that field. */
export const SECRET_FIELDS = ["password", "cardNumber", "cardCvv"];

/**
 * A copy of `item` with every secret field removed, plus the metadata the
 * detail view needs in their place: `secretLengths` (mask width) and
 * `passwordHealth` (computed here, where the password still exists).
 */
export function redactItem(item) {
  if (!item || typeof item !== "object") return item;

  const redacted = { ...item };
  const secretLengths = {};
  for (const field of SECRET_FIELDS) {
    const value = typeof item[field] === "string" ? item[field] : "";
    if (value) secretLengths[field] = value.length;
    delete redacted[field];
  }
  redacted.secretLengths = secretLengths;
  redacted.passwordHealth = passwordStrength(
    typeof item.password === "string" ? item.password : ""
  );
  return redacted;
}
