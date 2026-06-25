// Bastion Send client for the web app. Mirrors the extension's background
// logic, but as functions over the in-memory Account + bearer token (the web
// app is a single trusted context — no service worker). All crypto stays in
// WASM; the server only ever sees opaque blobs + published public identities.
import { api, ApiError, type SendPublic } from "./api";
import type { Account } from "./wasm";

// Reserved vault-item ids (must match crypto-wasm send_identity_item_id()).
export const SEND_IDENTITY_ID = "bastion:send-identity";
export const SEND_CONTACTS_ID = "bastion:send-contacts";

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
