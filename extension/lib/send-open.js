// Pin EVERY known contact: verifying a signature is independent of having
// compared safety numbers, and an unpinned id can be claimed with no
// signature at all. `signedOnly` below keeps the two facts apart.
function pinnedSenders(contacts) {
  return Object.fromEntries(
    (contacts || []).map((contact) => [contact.bastion_id, contact.public])
  );
}

/** `true` when the sender folded a passphrase into this blob's key derivation. */
export function isPassphraseProtected(blob) {
  return (
    typeof blob === "object" &&
    blob !== null &&
    !Array.isArray(blob) &&
    Object.prototype.hasOwnProperty.call(blob, "pw") &&
    blob.pw !== undefined
  );
}

/** Open one message with verified-contact enforcement entirely inside WASM. */
export function openMessage(account, contacts, blob, passphrase) {
  // A passphrase prompt must follow from the blob carrying a `pw` block, not
  // from a failed open: otherwise any undecryptable message (a junk envelope
  // the server injected, a tampered ciphertext) asks the user to type an
  // out-of-band Send passphrase into it.
  const passphraseRequired = isPassphraseProtected(blob);
  if (passphraseRequired && !passphrase) return { needsPass: true };

  let opened;
  try {
    opened = JSON.parse(
      account.send_open_with_pins(
        JSON.stringify(blob),
        passphrase || undefined,
        JSON.stringify(pinnedSenders(contacts))
      )
    );
  } catch {
    return {
      error: passphraseRequired
        ? "Wrong passphrase, or this message was tampered with."
        : "This message could not be decrypted — it may have been tampered with.",
    };
  }
  // Only a verified contact lends its display name; an unverified id is the
  // sender's own claim and must not borrow a name from the address book.
  const known = (contacts || []).find(
    (contact) => contact.bastion_id === opened.sender?.id
  );
  const verified = known && known.verified ? known : null;
  return {
    ...opened,
    display: verified ? verified.display : null,
    signedOnly: opened.sender?.state === "verified" && !verified,
  };
}
