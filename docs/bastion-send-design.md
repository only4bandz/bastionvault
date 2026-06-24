# Bastion Send — end-to-end encrypted notes between users (design doc, v0.1 DRAFT)

> Status: **draft for security audit** (Berbarus / Grok / Codex). Nothing here is
> implemented yet. The goal is to pin down the threat model and the exact
> cryptographic construction *before* writing code, because a mistake in
> public-key handling is fatal and silent.

## 1. Goal

Let a Bastion user send a **private note/message** to another Bastion user such
that **only the chosen recipient can decrypt it**, end-to-end, with the server
never seeing plaintext — "PGP-grade", built into the product.

- Each account has a public **Bastion ID** (a mailbox identifier, e.g. shown as
  `BSTN-4K2P-9XQ7`).
- To send, the sender picks the recipient's Bastion ID; the note is encrypted to
  that recipient's public key.
- **Optional passphrase**: the sender may add a secret phrase (shared
  out-of-band) as a second factor — then decryption needs *both* the recipient's
  key *and* the passphrase.

This reuses Bastion's existing primitives (Argon2id, HKDF, XChaCha20-Poly1305,
the zero-knowledge vault) and adds **asymmetric keys** (X25519, optional
Ed25519), which the core does not have yet.

### Non-goals (v0.1)
- Not a real-time chat. It's store-and-forward (like Bitwarden Send / encrypted
  email).
- Not metadata-hiding/anonymity network. The server learns routing metadata
  (who has a mailbox, that a blob is addressed to ID X, timing/size). Called out
  explicitly in §9.
- Not group messaging (1→1 only in v0.1).

## 2. Threat model

Adversaries we defend against:
- **Malicious / breached server.** Must not be able to read any note, recover
  private keys, or forge a note that decrypts as authentic. **Crucial:** must
  not be able to MITM by serving an attacker public key for a recipient ID
  (see §6 key verification).
- **Network attacker** (TLS assumed, but we don't rely on it for confidentiality
  — E2E is independent of transport).
- **Other users.** Cannot read notes not addressed to them; cannot enumerate
  who exists or brute-force mailbox IDs at scale (see §4).

Out of scope: a compromised endpoint (malware on the device reading decrypted
plaintext / the vault — same limitation as the rest of Bastion), and traffic
analysis / metadata (§9).

Trust assumptions: the recipient's **public key is authentic** — guaranteed only
if users verify the **safety number** (§6); otherwise reduces to trust-on-first-
use with the server as a trusted key directory (NOT acceptable for the
"military" promise; hence §6 is mandatory for that claim).

## 3. Identity keys

At account creation (or first use of Send), the client generates **two**
keypairs:

- **X25519** (`enc`) — for encryption (sealed-box recipient key).
- **Ed25519** (`sig`) — for optional sender authentication (§7).

Storage (zero-knowledge):
- **Private keys** are stored *inside the vault* (a reserved encrypted item, or
  a dedicated `keyring` blob), encrypted under the vault key like everything
  else. The server never sees them. They follow the vault across devices.
- **Public keys** are published to the server in a directory entry:
  `{ bastion_id, enc_pub, sig_pub, key_version, created_at, prev_key_fingerprint? }`.

Key generation uses the same CSPRNG path as the rest of crypto-core
(`OsRng` / browser `getRandomValues`).

## 4. Bastion ID (the "user number")

The user's example was a 7-digit number (`5943823`). **Recommendation: do NOT
use a short sequential/small number** — it is enumerable (≈10^7), enabling
mailbox discovery, spam targeting, and correlation.

Proposed instead (open for audit):
- **Random opaque ID**, ~80–100 bits, rendered in grouped Crockford base32:
  e.g. `BSTN-4K2P-9XQ7-J3MN` (shareable, non-sequential, not guessable).
- Optional human-friendly **handle** layered on top later (`alice#4821`) mapping
  to the opaque ID — but the cryptographic addressing always uses the opaque ID
  + verified key, never the handle.
- The directory lookup `ID → public keys` is **rate-limited** and ideally
  requires the exact full ID (no prefix search), so the directory can't be
  scraped.

Question for auditors: is an opaque random ID + safety-number verification
enough, or do we also want the directory to require an authenticated session to
resolve an ID (limits anonymous scraping but adds friction)?

## 5. Encryption construction (the core)

Envelope encryption with a per-message content key (CEK), so the optional
passphrase and the recipient key are independent layers.

**Send(plaintext, recipient_enc_pub, [passphrase], [sender_sig_priv]):**

1. `CEK ← random 32 bytes` (the symmetric key that actually encrypts the note).
2. Encrypt the note: `body = XChaCha20-Poly1305(key=CEK, nonce=random 24B,
   plaintext, aad=header_bytes)`. *(existing crypto-core AEAD)*
3. **Wrap CEK to the recipient (X25519 sealed box, age-style):**
   - `eph_priv, eph_pub ← X25519 keypair` (ephemeral, one per message).
   - `shared = X25519(eph_priv, recipient_enc_pub)`.
   - `wrap_key = HKDF-SHA256(ikm=shared, salt=eph_pub || recipient_enc_pub,
     info="bastion-send/v1/recipient")`. *(existing HKDF)*
   - `wrapped_cek_r = XChaCha20-Poly1305(key=wrap_key, nonce=random, CEK)`.
4. **Optional passphrase layer:** if a passphrase is given:
   - `pw_key = Argon2id(passphrase, salt=random 16B, params=policy)`. *(existing)*
   - `wrapped_cek_pw = XChaCha20-Poly1305(key=pw_key, nonce=random, CEK)`.
   - The recipient must unwrap **both** wrappings to recover CEK (we store CEK
     wrapped once by `wrap_key` then that result wrapped by `pw_key` — i.e.
     nested — OR require both independent unwraps; exact nesting order is an
     audit question, see §11).
5. **Optional signature:** `sig = Ed25519.sign(sender_sig_priv,
   transcript_hash)` where `transcript_hash = SHA-256(domain || eph_pub ||
   recipient_id || header || body)`. Included only in "signed" mode.
6. Output blob (stored on server, opaque):
   ```
   {
     v: 1,
     recipient_id,
     eph_pub,
     wrapped_cek_r,        // + nonce
     wrapped_cek_pw?,      // + nonce + argon2 params + salt  (if passphrase)
     body,                 // + nonce
     sender_id?, sig?,     // if signed
     expires_at?, read_once?,
   }
   ```

**Open(blob, my_enc_priv, [passphrase], [claimed sender_sig_pub]):** reverse —
derive `shared = X25519(my_enc_priv, eph_pub)`, same HKDF, unwrap CEK (and the
passphrase layer if present), AEAD-open the body; if signed, verify `sig`
against the sender's published `sig_pub` AND confirm that key's safety number.

Rationale: this is exactly the **libsodium `crypto_box_seal` / `age` X25519
recipient** pattern — well-studied, no custom crypto. AEAD failure is opaque
(can't distinguish wrong key vs tampering), consistent with the vault.

## 6. Key verification — **safety number** (mandatory for the trust claim)

Because the server distributes public keys, it could substitute its own. We
defeat this with a **safety number** (à la Signal):

- `safety_number = base10/QR( SHA-256( sort(enc_pub_A, enc_pub_B) ) )`,
  identical for both users.
- Shown in the UI; users compare it **out-of-band** (in person, call, other
  channel) once. After matching, the contact is **verified** and pinned (TOFU +
  explicit verification).
- If a contact's published key later changes (key rotation or attack), Bastion
  **warns loudly** and requires re-verification before sending.

Without verification we are TOFU-with-trusted-directory; with it we get real
MITM resistance. The UI should make "verified ✓ vs unverified" obvious.

## 7. Sender authenticity (anonymous vs signed)

- **Anonymous mode** (sealed box, no signature): recipient learns *nothing*
  verifiable about the sender. Good for whistleblowing / tip lines.
- **Signed mode** (Ed25519): recipient cryptographically confirms the sender's
  Bastion ID — but the sender's identity is revealed to the recipient.
- Proposal: **signed by default, with an explicit "send anonymously" toggle.**

## 8. Delivery / storage

- Sender: `POST /send` with the opaque blob → server stores it in the
  recipient's **inbox** keyed by `recipient_id`.
- Recipient: `GET /inbox` (authenticated) → pulls blobs → decrypts locally.
- **Read-once / expiry**: server enforces best-effort delete on first fetch
  and/or `expires_at` (defense-in-depth; the real protection is encryption, but
  this limits exposure window, Bitwarden-Send-style).
- Server stores only ciphertext + routing fields. Size caps + rate limits to
  prevent it being abused as bulk storage / spam.

## 9. Metadata (honest limitations)

The server *does* learn: which IDs have mailboxes, that a blob is addressed to
ID X, blob size, and timing. It does **not** learn content, sender (in anon
mode), or keys. True metadata privacy (mixnets, sealed sender) is **out of scope
for v0.1** and should be stated plainly in the UI ("contents are private; the
fact that you received something is not hidden from the server").

## 10. What reuses crypto-core vs what's new

Reused: Argon2id, HKDF-SHA256, XChaCha20-Poly1305 AEAD, CSPRNG, the
zero-knowledge vault for private-key storage.

New (to add, audited):
- `x25519-dalek` (ECDH) + the sealed-box wrap/unwrap.
- `ed25519-dalek` (optional signatures).
- Safety-number derivation + verified-contact state.
- Server: public-key **directory** + per-user **inbox** endpoints, rate limits.
- crypto-wasm bindings: `generate_identity`, `send_seal(...)`, `open_seal(...)`,
  `safety_number(a_pub, b_pub)`.

## 11. Open questions for the audit
1. **Passphrase layering**: nest (`pw(recip(CEK))`) vs two independent wraps of
   CEK? Which is safer / avoids confused-deputy? Should the passphrase instead
   feed into the HKDF `info`/`salt` rather than a separate AEAD layer?
2. **Bastion ID**: opaque-random vs handle#tag; does directory resolution need
   an authenticated session to limit scraping?
3. **Safety number**: is a sorted-pubkey SHA-256 sufficient, or adopt Signal's
   exact fingerprint (iterated hash + version) to resist any cross-protocol
   issues?
4. **Anonymous mode + read-once**: any deanonymization via timing/size? Is
   unauthenticated `POST /send` (so anon senders need no account) acceptable, or
   require an account to send?
5. **Key rotation / multi-device**: keys live in the vault (synced). What
   happens to in-flight messages when a user rotates keys or adds a device? Need
   a `key_version` and "decrypt with previous key" window?
6. **Domain separation**: are the HKDF `info` strings + AEAD AAD sufficient to
   prevent any blob from being replayed/confused across contexts (vault items vs
   send blobs vs manifest)?
7. **Replay / duplication**: should each blob carry a unique id + the recipient
   track seen ids to prevent replay?
8. **DoS / abuse**: inbox flooding by anyone who knows an ID — mitigations
   (rate limit, sender allow-list, proof-of-work, require account)?

## 12. Proposed phasing (after audit sign-off)
- P0: crypto-core X25519 seal/open + safety number + tests (no UI/server).
- P1: crypto-wasm bindings + identity generation stored in vault.
- P2: server directory + inbox endpoints (rate-limited).
- P3: extension/web UI — "Send", inbox, verify contact (safety number), signed
  vs anonymous, optional passphrase, read-once/expiry.
