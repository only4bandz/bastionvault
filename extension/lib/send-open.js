// Pin EVERY known contact: verifying a signature is independent of having
// compared safety numbers, and an unpinned id can be claimed with no
// signature at all. `signedOnly` below keeps the two facts apart.
function pinnedSenders(contacts) {
  return Object.fromEntries(
    (contacts || []).map((contact) => [contact.bastion_id, contact.public])
  );
}

/** Open one message with verified-contact enforcement entirely inside WASM. */
export function openMessage(account, contacts, blob, passphrase) {
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
    return passphrase
      ? { error: "Wrong passphrase or corrupted message." }
      : { needsPass: true };
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
