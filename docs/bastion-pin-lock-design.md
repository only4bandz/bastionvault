# Bastion Send — per-contact PIN lock (design v0.1)

> Status: **design for review** (not implemented). Sequel to
> [`bastion-send-design.md`](bastion-send-design.md). To be audited by
> Berbarus / Grok / Codex before any code, then built P0 (crypto) → P1 (wasm) →
> P2 (UI), each audited.

## 1. User story

On a contact, the user can **Enable a PIN**. Once enabled, every message
**received from that contact** is locked: opening it requires the PIN. The PIN
is chosen by the **recipient** (per contact), is **alphanumeric, free length
(≥4)** with a strength meter, and is **never stored anywhere**.

- Lose the PIN → those messages are **permanently unreadable** (by anyone,
  including the owner).
- The PIN **cannot be edited**. To change it: delete the contact and re-add it
  (new PIN); **all messages received before are lost**.
- A confirmation dialog with this warning is shown at PIN creation.

## 2. What this is — and is NOT (honest threat model)

The PIN is set by the **recipient after the fact**, so the only way to make
"lose it = unrecoverable" *true* is to **re-encrypt the received plaintext**
under a key derived from the PIN, and discard the identity-decryptable copy.

- ✅ **Defeats a glance at an unlocked vault**: someone with your unlocked
  Bastion still can't read that contact's messages without the PIN.
- ✅ **At-rest, double-wrapped**: the locked blob is stored as a vault item
  (already vault-encrypted) *and* PIN-encrypted — both are required.
- ❌ **NOT strong against an attacker who exfiltrates the locked blob.** A short
  PIN is low-entropy and brute-forceable offline:
  - `4 digits` ≈ 10⁴ → cracked ~instantly.
  - `6 alphanumeric` ≈ 36⁶ ≈ 2×10⁹ → minutes–hours even with a slow KDF.
  Argon2id (high cost) only *slows* this; it is not a substitute for entropy.
  The UI must show a **strength meter** and warn on short PINs.
- For genuinely strong protection, the **sender-set extra passphrase** (already
  shipped) remains the recommended path — a strong shared secret folded into the
  seal at send time.
- **Receipt→lock window**: a message is identity-decryptable from the moment it
  arrives until it is re-encrypted under the PIN. This window is inherent to a
  recipient-set PIN (the sender can't pre-apply it). We minimize it by locking at
  the earliest opportunity (see §5) and document it.

## 3. Cryptographic design

Per PIN-enabled contact, store (in the encrypted `bastion:send-contacts` item):

```
pin_enabled : true
pin_salt    : 16 random bytes        (NOT secret; enables the KDF)
pin_kdf     : { mem_kib, iters, par } (Argon2id params, tuned high for low entropy)
```

No PIN and **no PIN verifier** are stored (a verifier would be an offline
brute-force oracle). Wrong-PIN detection comes from the AEAD itself (§3.2).

### 3.1 Lock key

```
lock_key = Argon2id(pin, salt=pin_salt, params=pin_kdf)            // 32 bytes
```

Domain-separate from the vault KDF (distinct info/label, e.g.
`pm:v1:send/pin-lock`).

### 3.2 Locked message blob

When a message from a PIN-contact is received and opened via the identity:

```
locked = XChaCha20-Poly1305(
            key  = lock_key,
            nonce= random 24B,
            aad  = "pm:v1:send/pin-lock" ‖ contact_id ‖ message_id,
            pt   = { plaintext, sender_state, sender_id, created_at })
```

Use the **key-committing** AEAD construction already in `crypto-core` (the CEK
key-commitment used by Send), so that a wrong PIN fails closed rather than
risking a valid-looking decryption under the wrong key. The locked record is:

```
{ v:1, contact_id, message_id, salt:<from contact>, nonce, ct, created_at }
```

stored as a reserved vault item `bastion:send-locked:<message_id>` (vault-
encrypted on top → both vault key and PIN required to read).

### 3.3 Read

Enter PIN → derive `lock_key` → AEAD-open the stored blob. Failure (key
commitment / tag) → "Wrong PIN". No attempt counter is meaningful (offline
data), but the UI may rate-limit attempts to slow shoulder-surfing.

## 4. Data & storage model

- `Contact` gains `pin_enabled`, `pin_salt`, `pin_kdf` (no secret).
- New reserved namespace `bastion:send-locked:<id>` for locked messages (hidden
  from the vault list like other `bastion:send-*` items; synced across devices).
- Deleting a contact **also deletes its `bastion:send-locked:*` items** (the
  warning's "messages lost" guarantee).

## 5. Flows

**Enable PIN** (contact detail): confirmation modal with the warning (§1) →
PIN entry (alphanumeric, strength meter, ≥4) → store `pin_salt`/`pin_kdf` on the
contact. Existing already-received messages from that contact (if any) are
locked now (prompting once for the PIN to encrypt them).

**Receive** (inbox fetch): for each message whose sender is a PIN-contact:
1. open via identity → plaintext;
2. if the PIN-derived `lock_key` is available this session, re-encrypt → store
   `bastion:send-locked:<id>` → `DELETE /send/inbox/:id`;
3. if not, surface "N message(s) from <contact> need your PIN to secure" and
   keep them server-side (still identity-openable) until the user supplies the
   PIN. *(Open question — see §7.)*

**Read**: open a locked message → PIN prompt → decrypt → show with the usual
trust banner. Read-once delete still applies to the *local* locked copy if the
user deletes it.

**Change PIN**: not supported. UI directs to delete + re-add the contact
(explicit second warning).

## 6. UX

- Contact detail/row: a **"PIN lock"** toggle + status (🔒 on / off).
- Strength meter on PIN entry; inline warning for short/low-entropy PINs.
- Locked inbox rows show a 🔒 and "Locked — enter PIN" instead of a preview.
- Warning + confirmation copy per §1 (FR + EN).
- Both surfaces (extension + web app), reusing the shared Send client.

## 7. Open questions for reviewers

1. **Receipt→lock window** (§5 step 3): best handling? Options — (a) require the
   PIN at fetch and refuse to display until locked; (b) lock opportunistically
   and warn while unlocked; (c) a session "PIN cache" to auto-lock new messages.
   Trade-offs between security and the auto-fetch UX.
2. **Argon2id params** for a 4–12 char PIN run in WASM on every open: how high
   can cost go before the read latency hurts? Is per-contact tuning worth it?
3. **Key commitment / wrong-PIN**: confirm the Send CEK-commitment construction
   is the right primitive here; any pitfall reusing it for PIN keys?
4. **Storage growth & dedupe**: locked items accumulate (no server quota now).
   Cap? Idempotency if two devices lock the same message concurrently.
5. **Metadata**: the server still learns sender/recipient/timing before lock
   (unchanged from Send §9). Anything new leaked by the lock scheme?
6. **Is re-encryption worth it** vs. just steering users to the existing strong
   sender-passphrase? (We chose re-encryption to honor the "unrecoverable"
   semantic; reviewers should sanity-check that trade-off.)

## 8. Non-goals (v0.1)

PIN recovery, PIN change, biometric unlock, server-side enforcement (the server
stays oblivious — it only sees opaque blobs and the read-once delete).
