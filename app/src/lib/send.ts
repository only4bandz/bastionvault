// Bastion Send client for the web app. Mirrors the extension's background
// logic, but as functions over the in-memory Account + bearer token (the web
// app is a single trusted context — no service worker). All crypto stays in
// WASM; the server only ever sees opaque blobs + published public identities.
import { api, ApiError, type Blob, type SendPublic } from "./api";
import { send_safety_number, type Account } from "./wasm";

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
  try {
    return JSON.parse(account.decrypt_item(JSON.stringify(blob), SEND_CONTACTS_ID)) as Contact[];
  } catch {
    return [];
  }
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
