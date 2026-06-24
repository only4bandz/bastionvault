// Thin loader around the Rust crypto-core compiled to WebAssembly.
// All cryptography (Argon2id, Secret Key, XChaCha20-Poly1305, key wrapping)
// runs here, in the browser — the same audited core used everywhere.
import init, {
  register,
  register_with,
  unlock,
  type Account,
} from "../pkg/crypto_wasm.js";

let ready: Promise<unknown> | null = null;

/** Initialize the WASM module once (idempotent). */
export function ensureWasm(): Promise<unknown> {
  if (!ready) ready = init();
  return ready;
}

export { register, register_with, unlock };
export type { Account };

/** Shape returned by `Account.reveal_secret` (one-shot). */
export interface RevealedSecret {
  secret_key: string;
  emergency_kit: string;
}
