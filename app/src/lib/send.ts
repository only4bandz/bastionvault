// Bastion Send client for the web app. Mirrors the extension's background
// logic, but as functions over the in-memory Account + bearer token (the web
// app is a single trusted context — no service worker). All crypto stays in
// WASM; the server only ever sees opaque blobs + published public identities.
import { api, ApiError, type Blob, type InboxItem, type SendPublic } from "./api";
import { send_safety_number, type Account } from "./wasm";

export type { InboxItem };

// Reserved vault-item ids (must match crypto-wasm send_identity_item_id()).
export const SEND_IDENTITY_ID = "bastion:send-identity";
export const SEND_CONTACTS_ID = "bastion:send-contacts";

/** A pinned contact (the full PublicIdentity is pinned, BR4 — not key_version). */
export interface Contact {
  bastion_id: string;
  public: SendPublic;
  pinFp: string;
  display: string;
  verified: boolean;
  verified_at: number | null;
  safety_number: string | null;
}

// Canonical JSON of a PublicIdentity (stable key order) for fingerprinting.
const canonPublic = (pub: SendPublic): string => JSON.stringify(pub, Object.keys(pub).sort());
async function sha256hex(str: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export interface SendState {
  enabled: boolean;
  bastionId: string | null;
}

/** Whether Send is enabled on this account, and the published Bastion address. */
export async function sendState(account: Account, token: string): Promise<SendState> {
  const enabled = account.has_send_identity;
  let bastionId: string | null = null;
  if (enabled) {
    try {
      bastionId = (await api.whoami(token)).bastion_id;
    } catch {
      bastionId = null; // enabled locally but not published yet
    }
  }
  return { enabled, bastionId };
}

/**
 * Enable Send (BR3, whoami-guarded). Only mints a new identity when the account
 * has none published (whoami 404); otherwise re-publishes the existing one to
 * recover the stable Bastion id. Returns the address or a user-facing error.
 */
export async function sendEnable(account: Account, token: string): Promise<{ bastionId: string } | { error: string }> {
  let who: { bastion_id: string; public: SendPublic } | null = null;
  try {
    who = await api.whoami(token);
  } catch (e) {
    if (!(e instanceof ApiError && e.status === 404)) throw e;
  }
  if (!account.has_send_identity) {
    if (who) {
      return { error: "Send is already enabled on another device. Unlock that device to use Send here." };
    }
    const itemBlob = JSON.parse(account.create_send_identity());
    await api.putItem(token, SEND_IDENTITY_ID, itemBlob);
  }
  const bastionId =
    who?.bastion_id ?? (await api.publishIdentity(token, JSON.parse(account.send_identity_public()) as SendPublic)).bastion_id;
  return { bastionId };
}

// ── contacts (BR7: stored in the encrypted reserved item bastion:send-contacts) ──

/** Decrypt the contacts list out of the vault items (held in App state). */
export function loadContacts(account: Account, items: Record<string, Blob>): Contact[] {
  const blob = items[SEND_CONTACTS_ID];
  if (!blob) return [];
  const contacts: unknown = JSON.parse(account.decrypt_item(JSON.stringify(blob), SEND_CONTACTS_ID));
  if (
    !Array.isArray(contacts) ||
    !contacts.every(
      (contact) =>
        contact &&
        typeof contact === "object" &&
        typeof (contact as Contact).bastion_id === "string" &&
        typeof (contact as Contact).public === "object" &&
        typeof (contact as Contact).pinFp === "string" &&
        typeof (contact as Contact).display === "string" &&
        typeof (contact as Contact).verified === "boolean" &&
        ((contact as Contact).verified_at === null || typeof (contact as Contact).verified_at === "number") &&
        ((contact as Contact).safety_number === null || typeof (contact as Contact).safety_number === "string")
    )
  ) {
    throw new Error("invalid contacts payload");
  }
  return contacts as Contact[];
}

/** Persist the contacts list as the encrypted reserved vault item. */
export async function saveContacts(account: Account, token: string, contacts: Contact[]): Promise<void> {
  const blob = JSON.parse(account.encrypt_item(JSON.stringify(contacts), SEND_CONTACTS_ID)) as Blob;
  await api.putItem(token, SEND_CONTACTS_ID, blob);
}

export interface Resolved {
  bastionId: string;
  public: SendPublic;
  pinFp: string;
  safety_number: string;
}

/** Resolve a Bastion address → its public identity + the A↔B safety number. */
export async function resolveContact(
  account: Account,
  token: string,
  rawId: string
): Promise<Resolved | { error: string }> {
  const id = rawId.trim().toUpperCase();
  if (!id) return { error: "Enter a Bastion address." };
  if (!account.has_send_identity) return { error: "Enable Send first." };
  let myId: string;
  try {
    myId = (await api.whoami(token)).bastion_id;
  } catch {
    return { error: "Publish your own address first." };
  }
  if (id === myId) return { error: "That's your own address." };
  let theirPub: SendPublic;
  try {
    theirPub = await api.directory(token, id);
  } catch (e) {
    return { error: e instanceof ApiError && e.status === 404 ? "No Bastion user has that address." : "Lookup failed." };
  }
  const myPub = JSON.parse(account.send_identity_public()) as SendPublic;
  const safety = send_safety_number(myId, JSON.stringify(myPub), id, JSON.stringify(theirPub));
  const pinFp = await sha256hex(canonPublic(theirPub));
  return { bastionId: id, public: theirPub, pinFp, safety_number: safety };
}

export interface ComposeOpts {
  passphrase?: string;
  signed: boolean;
  expiresAt?: number | null;
}

const SIGNING_UNAVAILABLE =
  "Your sender identity could not be confirmed. Nothing was sent; retry or choose anonymous mode explicitly.";

async function senderIdForMode(
  signed: boolean,
  lookup: () => Promise<string>
): Promise<string | undefined> {
  if (!signed) return undefined;
  const id = await lookup();
  if (!id) throw new Error(SIGNING_UNAVAILABLE);
  return id;
}

/**
 * Seal a note to a contact (BR6: to the PINNED key, never a fresh directory
 * fetch) and deliver it. For a verified contact, refuse if the published key
 * changed since we pinned it.
 */
export async function composeNote(
  account: Account,
  token: string,
  contact: Contact,
  plaintext: string,
  opts: ComposeOpts
): Promise<{ ok: true } | { error: string; keyChanged?: boolean }> {
  if (!plaintext.trim()) return { error: "Write a note first." };
  if (contact.verified) {
    try {
      const live = await api.directory(token, contact.bastion_id);
      if ((await sha256hex(canonPublic(live))) !== contact.pinFp) return { error: "key-changed", keyChanged: true };
    } catch {
      /* directory unreachable → fall back to the pinned key (offline) */
    }
  }
  let myId: string | undefined;
  try {
    myId = await senderIdForMode(opts.signed, async () => (await api.whoami(token)).bastion_id);
  } catch {
    return { error: SIGNING_UNAVAILABLE };
  }
  const blob = JSON.parse(
    account.send_seal(
      plaintext,
      contact.bastion_id,
      JSON.stringify(contact.public),
      opts.passphrase || undefined,
      myId
    )
  ) as { recipient_id: string; message_id: string };
  try {
    await api.sendBlob(token, {
      recipient_id: blob.recipient_id,
      message_id: blob.message_id,
      blob,
      expires_at: opts.expiresAt ?? null,
    });
  } catch (e) {
    const code = e instanceof ApiError ? e.status : 0;
    const map: Record<number, string> = {
      413: "Message is too large (256 KiB max).",
      409: "This message was already sent.",
      429: "Too many sends, or the recipient's inbox is full. Try again later.",
      404: "Recipient not found — they may have disabled Send.",
      0: "Server unreachable. Nothing was sent.",
    };
    return { error: map[code] || (e as Error)?.message || "Send failed." };
  }
  return { ok: true };
}

// ── inbox ──

export interface Opened {
  plaintext?: string;
  sender?: { state: string; id: string | null };
  display?: string | null;
  keyChanged?: boolean;
  needsPass?: boolean;
  error?: string;
}

/**
 * Open one inbox blob (BR5 two-pass): pass 1 with no verifier discovers the
 * sender; for a known VERIFIED contact, re-open against the PINNED public to
 * reach "verified" — a signature failure there means the key changed.
 */
export function openMessage(account: Account, contacts: Contact[], blob: unknown, passphrase?: string): Opened {
  let r1: { plaintext: string; sender: { state: string; id: string | null } };
  try {
    r1 = JSON.parse(account.send_open(JSON.stringify(blob), passphrase || undefined, undefined));
  } catch {
    return passphrase ? { error: "Wrong passphrase or corrupted message." } : { needsPass: true };
  }
  let sender = r1.sender;
  let keyChanged = false;
  if (sender.state === "unverified" && sender.id) {
    const v = contacts.find((c) => c.bastion_id === sender.id && c.verified);
    if (v) {
      try {
        sender = JSON.parse(account.send_open(JSON.stringify(blob), passphrase || undefined, JSON.stringify(v.public))).sender;
      } catch {
        keyChanged = true;
      }
    }
  }
  const known = contacts.find((c) => c.bastion_id === sender.id);
  return { plaintext: r1.plaintext, sender, display: known?.display ?? null, keyChanged };
}

export const inboxList = (token: string): Promise<InboxItem[]> => api.inbox(token);
export const inboxDelete = (token: string, messageId: string): Promise<void> => api.inboxDelete(token, messageId);
