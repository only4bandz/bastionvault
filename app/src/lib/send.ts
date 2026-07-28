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
  lock_enabled?: true;
  lock_salt?: string;
  lock_kdf?: { mem_kib: number; iterations: number; parallelism: number };
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

export type PersistEncryptedItem = (id: string, blob: Blob) => Promise<void>;
const MAX_CONTACTS = 1_000;
const MAX_CONTACT_DISPLAY_BYTES = 200;
const MAX_DATE_MS = 8_640_000_000_000_000;

function exactRecord(value: unknown, keys: string[]): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.keys(value).length === keys.length &&
    keys.every((key) => Object.prototype.hasOwnProperty.call(value, key))
  );
}

function validPublicIdentity(value: unknown): value is SendPublic {
  return (
    exactRecord(value, ["enc_pub", "sig_pub", "key_version"]) &&
    value.key_version === 1 &&
    Array.isArray(value.enc_pub) &&
    value.enc_pub.length === 32 &&
    value.enc_pub.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255) &&
    Array.isArray(value.sig_pub) &&
    value.sig_pub.length === 32 &&
    value.sig_pub.every((byte) => Number.isSafeInteger(byte) && byte >= 0 && byte <= 255)
  );
}

export function requireContactsPayload(value: unknown): Contact[] {
  if (!Array.isArray(value) || value.length > MAX_CONTACTS) {
    throw new Error("invalid contacts payload");
  }
  const ids = new Set<string>();
  for (const contact of value) {
    const hasLockMetadata =
      typeof contact === "object" &&
      contact !== null &&
      !Array.isArray(contact) &&
      ["lock_enabled", "lock_salt", "lock_kdf"].some((key) =>
        Object.prototype.hasOwnProperty.call(contact, key)
      );
    if (
      !exactRecord(contact, [
        "bastion_id",
        "public",
        "pinFp",
        "display",
        "verified",
        "verified_at",
        "safety_number",
        ...(hasLockMetadata ? ["lock_enabled", "lock_salt", "lock_kdf"] : []),
      ]) ||
      typeof contact.bastion_id !== "string" ||
      !/^[A-Z2-7]{25}[AEIMQUY4]$/.test(contact.bastion_id) ||
      ids.has(contact.bastion_id) ||
      !validPublicIdentity(contact.public) ||
      typeof contact.pinFp !== "string" ||
      !/^[0-9a-f]{64}$/.test(contact.pinFp) ||
      typeof contact.display !== "string" ||
      contact.display.length === 0 ||
      new TextEncoder().encode(contact.display).byteLength > MAX_CONTACT_DISPLAY_BYTES ||
      typeof contact.verified !== "boolean" ||
      (contact.verified_at !== null &&
        (!Number.isSafeInteger(contact.verified_at) ||
          (contact.verified_at as number) < 0 ||
          (contact.verified_at as number) > MAX_DATE_MS)) ||
      (contact.safety_number !== null &&
        (typeof contact.safety_number !== "string" ||
          !/^[0-9]{60}$/.test(contact.safety_number))) ||
      (contact.verified &&
        (contact.verified_at === null || contact.safety_number === null)) ||
      (!contact.verified && contact.verified_at !== null)
    ) {
      throw new Error("invalid contacts payload");
    }
    if (
      hasLockMetadata &&
      (contact.lock_enabled !== true ||
        typeof contact.lock_salt !== "string" ||
        !/^(?:[A-Za-z0-9+/]{4}){5}[A-Za-z0-9+/][AQgw]==$/.test(contact.lock_salt) ||
        !exactRecord(contact.lock_kdf, ["mem_kib", "iterations", "parallelism"]) ||
        !Number.isSafeInteger(contact.lock_kdf.mem_kib) ||
        (contact.lock_kdf.mem_kib as number) < 19 * 1024 ||
        (contact.lock_kdf.mem_kib as number) > 128 * 1024 ||
        !Number.isSafeInteger(contact.lock_kdf.iterations) ||
        (contact.lock_kdf.iterations as number) < 2 ||
        (contact.lock_kdf.iterations as number) > 6 ||
        !Number.isSafeInteger(contact.lock_kdf.parallelism) ||
        (contact.lock_kdf.parallelism as number) < 1 ||
        (contact.lock_kdf.parallelism as number) > 4)
    ) {
      throw new Error("invalid contacts payload");
    }
    ids.add(contact.bastion_id);
  }
  return value as Contact[];
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
export async function sendEnable(
  account: Account,
  token: string,
  persistEncryptedItem: PersistEncryptedItem
): Promise<{ bastionId: string } | { error: string; requiresLock?: boolean }> {
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
    const itemBlob = JSON.parse(account.create_send_identity()) as Blob;
    try {
      await persistEncryptedItem(SEND_IDENTITY_ID, itemBlob);
    } catch {
      // create_send_identity installs the new private identity in WASM before
      // returning its encrypted vault item. Locking is required to discard that
      // staged identity when persistence was not confirmed.
      return {
        error: "Send identity persistence failed. Unlock the vault before retrying.",
        requiresLock: true,
      };
    }
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
  return requireContactsPayload(contacts);
}

/** Persist the contacts list as the encrypted reserved vault item. */
export async function saveContacts(
  account: Account,
  contacts: Contact[],
  persistEncryptedItem: PersistEncryptedItem
): Promise<void> {
  const blob = JSON.parse(account.encrypt_item(JSON.stringify(contacts), SEND_CONTACTS_ID)) as Blob;
  await persistEncryptedItem(SEND_CONTACTS_ID, blob);
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
  /** The message named a known contact but carried no signature at all. */
  forgedSender?: boolean;
  /**
   * The signature checked out against the key pinned for this contact, but
   * the user has not compared safety numbers out of band. Distinct from a
   * fully verified contact: the pin itself came from the server.
   */
  signedOnly?: boolean;
  needsPass?: boolean;
  error?: string;
}

/**
 * Open one inbox blob. WASM discovers the sealed sender and, for a verified
 * contact, re-opens against the pinned public key before returning plaintext.
 * A signature failure returns only key-change metadata.
 */
export function openMessage(account: Account, contacts: Contact[], blob: unknown, passphrase?: string): Opened {
  // Pin EVERY known contact, not only safety-number-verified ones: checking a
  // signature is independent of having compared safety numbers, and a sender
  // that was never pinned could claim any id without one (see
  // CryptoError::UnsignedSenderClaim). Whether the pin is trustworthy is a
  // separate question, answered by `signedOnly` below.
  const pinned = Object.fromEntries(
    contacts.map((contact) => [contact.bastion_id, contact.public])
  );
  let opened: Opened;
  try {
    opened = JSON.parse(
      account.send_open_with_pins(
        JSON.stringify(blob),
        passphrase || undefined,
        JSON.stringify(pinned)
      )
    ) as Opened;
  } catch {
    return passphrase ? { error: "Wrong passphrase or corrupted message." } : { needsPass: true };
  }
  const known = contacts.find((contact) => contact.bastion_id === opened.sender?.id);
  // A contact's name is only ever lent to a sender the user verified out of
  // band. Resolving it for an unverified — that is, self-asserted — id let a
  // stranger who knew the address wear that contact's name in the inbox, with
  // the victim's own address book supplying the credibility.
  const verifiedContact = known?.verified ? known : undefined;
  return {
    ...opened,
    display: verifiedContact?.display ?? null,
    signedOnly: opened.sender?.state === "verified" && !verifiedContact,
  };
}

export const inboxList = (token: string): Promise<InboxItem[]> => api.inbox(token);
export const inboxDelete = (token: string, messageId: string): Promise<void> => api.inboxDelete(token, messageId);
