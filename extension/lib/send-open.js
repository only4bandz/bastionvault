function pinnedSenders(contacts) {
  return Object.fromEntries(
    (contacts || [])
      .filter((contact) => contact.verified)
      .map((contact) => [contact.bastion_id, contact.public])
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
  const known = (contacts || []).find(
    (contact) => contact.bastion_id === opened.sender?.id
  );
  return { ...opened, display: known?.display || null };
}
