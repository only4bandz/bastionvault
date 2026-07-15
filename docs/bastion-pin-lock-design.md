# Bastion Send — per-contact lock phrase (design v0.2)

> Status: **audit-incorporated, ready to build P0.** Sequel to
> [`bastion-send-design.md`](bastion-send-design.md). Reviewed by
> Berbarus / Grok / Codex (v0.1 = NO-GO; this v0.2 folds in every required
> change). Build order: P0 (crypto-core) → P1 (wasm) → P2 (UI), each audited.
>
> v0.1 → v0.2 changes (all from the review): renamed **PIN → lock phrase**, min
> length **8**; honest narrowed guarantee; **single-call lock-finalization**
> crypto primitive (plaintext never crosses into JS); **finalized/pending** state
> machine; locked item id is a **fresh random id** (not the server-visible
> `message_id`); explicit **`lock_commit`** + HKDF domain + **length-prefixed
> AAD**; WASM-safe Argon2id params (**p=1**); hard-delete + quota; forgery note.

## 1. User story

On a contact, the user can **Enable a lock phrase**. Once enabled, every message
**received from that contact** is re-encrypted under that phrase: opening it
requires the phrase. The phrase is chosen by the **recipient** (per contact), is
**alphanumeric, minimum 8 characters** with a strength meter, and is **never
stored anywhere**.

- Forget the phrase → those locked copies are **unreadable, even by you** (see
  the precise guarantee in §2 — this is not "unrecoverable by anyone").
- The phrase **cannot be edited**. To change it: delete the contact and re-add
  it (new phrase); **the locked copies are destroyed**.
- A confirmation dialog with the §2 warning is shown at creation.

**Confirmation copy (FR):**
> **⚠️ Phrase de verrouillage — à lire avant de continuer**
> Les messages reçus de ce contact seront re-chiffrés sous cette phrase.
> • La phrase n'est **stockée nulle part**. Si tu l'oublies, **tu ne pourras
>   plus lire** ces copies verrouillées — elles seront perdues.
> • Une phrase **courte peut être cassée** par quelqu'un qui vole ta copie
>   verrouillée. Utilise **au moins 8 caractères**, idéalement une phrase. Pour
>   une vraie confidentialité, demande à l'expéditeur d'ajouter un **passphrase
>   d'envoi** (plus fort).
> • La phrase **ne peut pas être changée** : pour en changer, supprime puis
>   recrée le contact (les copies verrouillées actuelles seront détruites).
> [ Annuler ]  [ J'ai compris — activer ]

## 2. Threat model — the precise guarantee (honest)

The original message is sealed to your long-lived **X25519 identity key**, which
stays in your vault forever (Send §11 forbids deleting old enc keys). A
recipient-set lock phrase therefore **protects nothing about the original
ciphertext**; it only governs a **retained, re-encrypted copy** after the
identity-decryptable copies are gone.

> **Guarantee.** A finalized locked message is readable only with
> `(vault key) AND (lock phrase)`. Strength against an attacker who already holds
> your **unlocked vault but not the phrase** = the **phrase's entropy** (the lock
> phrase is offline-guessable from the locked blob; Argon2id only slows it).

**What it does NOT protect against (must stay in the UI/docs):**
- A **malicious or breached server** — Bastion's primary declared adversary
  (Send §2) — already holds the original blob, and read-once delete is
  best-effort (Send §8). That copy stays decryptable with the identity key, **no
  phrase needed**. So the feature is **not** "unrecoverable by anyone."
- A **low-entropy phrase**: offline brute-force from the locked blob + the
  (non-secret) salt/params. Realistic offline attacker (native Argon2 + GPU
  parallelism): `4 digits` instant · `6 alnum` minutes–hours · `8 alnum` weeks–
  years · `≥12 / passphrase` infeasible. The meter must estimate **offline-
  attacker** time (not the WASM open cost, which is ~10⁶× smaller).
- **The receipt→lock window** (§5): until a message is finalized, the original is
  identity-decryptable. Inherent to a recipient-set secret; minimized by §5.

**Honest positioning (UI copy + README):** a lock phrase is a **glance defense /
local compartment** (someone with your unlocked vault still can't read that
contact's messages), **not** strong end-to-end secrecy. For the latter, steer
users to the **sender-set passphrase** (folded into the seal at send time; the
server has no offline oracle on it at all — Send §5.4).

## 3. Naming & strength policy

- UI term: **"lock phrase" / "phrase de verrouillage"** (not "PIN").
- **Minimum 8** alphanumeric chars; **reject < 8** and obviously weak/common
  values. Recommend **≥12 or a passphrase**.
- **Strength meter measured against an offline GPU attacker** at the chosen
  Argon2id params (e.g. "8 chars ≈ weeks on a funded rig", "a 4-word passphrase ≈
  infeasible"). Never show the WASM open latency as "strength".
- Not editable (per §1).

## 4. Cryptographic construction

Per lock-enabled contact, store in the encrypted `bastion:send-contacts` item:

```
lock_enabled : true
lock_salt    : 16 random bytes            (non-secret)
lock_kdf     : { v, mem_kib, iters, par } (versioned Argon2id params; see §4.1)
```

No phrase and **no separate verifier** are stored. The only verifier is the
Argon2-gated commitment/tag (§4.3) — there is **no cheaper-than-Argon2 oracle**.

### 4.1 KDF — WASM-safe, p=1

Browser WASM is effectively single-threaded (no SharedArrayBuffer by default), so
**`parallelism = 1`** — `p>1` would not help the defender but *would* help a
multi-core attacker.

```
lock_kdf default (v1): { mem_kib: 131072 (128 MiB), iters: 3, par: 1 }
```

Tune `iters` so a single open is ~250–500 ms on a mid-tier mobile WASM target;
**memory is the only real anti-GPU lever** — keep it as high as the latency
budget allows (≤ existing `MAX_MEM_KIB`). Params are **versioned and stored with
the contact** so future contacts can use stronger values without breaking old
locked blobs.

The WASM build caps attacker-controlled Argon2 work at **128 MiB, 6 passes,
and p=4** before allocating. The v1 lock default sits at that memory ceiling
with 3 passes and p=1. Native builds keep their larger compatibility ceiling;
browser clients fail closed on records above the browser budget.

### 4.2 Lock key — Argon2id then HKDF domain

```
ikm      = Argon2id(phrase, salt = lock_salt, params = lock_kdf)   // 32 B
lock_key = HKDF-SHA256(ikm, info = "pm:v1:send/pin-lock")          // 32 B
```

Domain-separated from the vault KDF and the Send seal's `pw_material`. Add the
`pm:v1:send/pin-lock*` constants to the canonical domain set in `send.rs`, with a
test asserting no collision with vault or other Send domains.

### 4.3 Locked record — commitment + AEAD + length-prefixed AAD

```
lock_commit = HKDF-SHA256(lock_key, info = "pm:v1:send/pin-lock/commit")   // 32 B

aad = LP("pm:v1:send/pin-lock") ‖ version(u8=1) ‖ LP(contact_id)
      ‖ LP(message_id) ‖ LP(serialize(lock_kdf)) ‖ LP(lock_salt)
      // LP(x) = u32-BE length ‖ x  (big-endian, matching send.rs `put`);
      // the version is a single raw byte (consistent with Send's header AAD).
      // serialize(lock_kdf) = mem_kib(u32-BE) ‖ iters(u32-BE) ‖ par(u32-BE).
      // created_at is a display-only field — deliberately NOT in the AAD/body.

ct  = XChaCha20-Poly1305(key = lock_key, nonce = random 24B, aad,
                         pt = canonical{ plaintext, sender_state, sender_id })
```

Open: derive `lock_key`, check `lock_commit` in **constant time** (`ct_eq`), then
AEAD-open with the same AAD. Any mismatch ⇒ opaque `Aead/Malformed` error; **no
partial plaintext ever leaves the crypto layer**. Reuse the audited
key-committing discipline from Send (CEK commit) — but `lock_commit` is its own
field (there is no `wrap_key` here).

**Locked record (the vault item value):**
```
{ v:1, local_id, contact_id, message_id, lock_commit, body: EncryptedBlob, created_at }
   // body (nonce + ct) is the XChaCha20-Poly1305 EncryptedBlob from §4.3
```
- `local_id`: **fresh random 128-bit id**. The vault item key is
  `bastion:send-locked:<local_id>` — **never** the server-visible `message_id`
  (see §7 leak). `message_id` is stored here too, but only inside the
  **vault-encrypted** record (not a server-visible position) and is AAD-bound.
- **Single salt source**: the salt comes from the contact only; it is bound via
  AAD but **not** duplicated as a separate mutable field in the record.
- `contact_id` must be **stable and unique**; a delete+re-add MUST mint a new
  `contact_id` so an old locked blob can never bind onto a new contact.

### 4.4 Forgery note (document it)

Once the original is dropped, a locked message's sender trust
(Verified/Unverified) is authenticated under `lock_key`, **not** re-checkable
against the sender's Ed25519 signature (the original is gone). Someone with the
phrase **and** vault-write could forge a "Verified from Alice" locked record.
That attacker already owns the vault — acceptable, but stated.

## 5. Lock finalization — single-call primitive + state machine

**The sealed-sender problem (why a pre-open gate is impossible):** the sender id
lives *inside* the Send ciphertext (Send §7). You cannot know a message is from a
lock-contact without first identity-decrypting it. So the window cannot be closed
by "don't open lock-contact messages" — it can only be made **no-persist**.

**P0 primitive (crypto-core / wasm):** one call does the whole sensitive step and
returns **only the locked JSON** — the plaintext never crosses into JS:

```
finalize_locked(send_blob, recipient_identity, contact_id, message_id, lock_phrase,
                lock_salt, lock_kdf) -> locked_record_json
   // internally: send_open(identity) -> plaintext (in WASM only)
   //           -> derive lock_key -> commit + AEAD-seal -> return locked record
```

**Client state machine per message from a lock-enabled contact:**
```
fetched → (finalize_locked in WASM) → vault PUT locked item → verify stored
        → DELETE /send/inbox/:message_id → FINALIZED
```
- **No-persist rule:** the identity-decryptable plaintext and the original blob
  are **never** written to disk / IndexedDB / cache / React-persisted state. Only
  the locked record is persisted.
- If the lock phrase is **not available** this session: do **not** identity-open
  for display. Leave the blob on the server (no new exposure — it's already
  there) and show a **"🔒 locked — enter phrase to secure & view"** placeholder.
- The **"unrecoverable" guarantee applies only to FINALIZED items.** If vault PUT
  or DELETE fails, mark the item **pending** and retry DELETE; surface "not yet
  secured".
- **Every device**, immediately after identity-decrypting any inbox blob, MUST
  check `sender_id ∈ lock_enabled contacts`; if so it must **refuse to display or
  persist** the plaintext and route only through `finalize_locked` (or discard +
  leave on server). This is a hard rule, not "if a key is available".
- **No "open without locking"** action exists for lock-enabled contacts.

Residual, documented: an **irreducible in-RAM window** during the WASM open, and
the server's retained original if it ignores DELETE (§2).

## 6. Multi-device & concurrency

- `lock_enabled` + `lock_salt` + `lock_kdf` sync via the contacts item; the
  **phrase / lock_key never sync** and are device-local-volatile (cleared on
  vault lock).
- A device **without** the phrase that auto-fetches MUST apply the §5 hard rule:
  after identity-decrypt, detect a lock-contact sender and **not** display/persist
  — show the locked placeholder. (Prevents the "other device opens it first"
  bypass.)
- **Idempotency:** before finalizing, check whether a locked item for this
  `message_id` already exists (scan locked items' AAD-bound `message_id`, or keep
  a small synced index); if so, skip and just ensure DELETE. Concurrent finalizes
  converge (each is independently openable with the phrase); DELETE tolerates
  already-deleted.
- An optional **session phrase cache** (auto-lock new arrivals) is opt-in, local,
  bounded, cleared on lock/tab-hide, and explicitly **outside** the guarantee.

## 7. Data model, deletion & abuse

- **New metadata leak fixed:** the locked item id is a **random `local_id`**, so
  the sync server cannot correlate "inbox `message_id=X` deleted" ↔ "vault item
  appeared". `message_id` never appears in a server-visible position.
- **Deletion semantics (narrowed):** deleting a contact **hard-deletes** its
  `bastion:send-locked:*` items (no ciphertext tombstones / soft-delete) and its
  contact entry. This destroys **the local locked copies on synced devices** — it
  does **not** destroy any original the server may have retained (§2). State it
  exactly that way.
- **Quota:** locked items escape the server inbox quota → unbounded vault growth.
  Add a **per-contact cap** + a user "purge locked messages" control + defined
  behavior when finalization/vault-write fails.
- Server metadata is otherwise unchanged (sender/recipient/timing already known
  pre-delete; coarse fetch→delete→PUT timing is observable — noted).

## 8. P0 crypto-core API surface (to build + KAT-test)

- `lock_finalize(send_blob, identity, contact_id, message_id, phrase, salt, kdf) -> LockedRecord`
  (open-in-WASM → derive → commit+seal; returns locked record only).
- `lock_open(locked_record, phrase) -> { plaintext, sender_state, sender_id, created_at }`
  (derive → constant-time commit check → AEAD-open; wrong phrase ⇒ opaque error).
- Domain constants `pm:v1:send/pin-lock` + `/commit`; length-prefixed AAD helper.
- **KATs:** round-trip; wrong phrase ⇒ `Aead/Malformed` (never plaintext);
  commitment tamper ⇒ reject; AAD swap (cross-contact, cross-message) ⇒ reject;
  domain-separation test; `p=1` params honored.

## 9. Non-goals (v0.2)

Phrase recovery, phrase change, biometric unlock, server-side enforcement, and a
PAKE/online-throttled gate (would need a non-oblivious server — conflicts with
the zero-knowledge / malicious-server model; it's the only way to make a short
secret truly safe, noted for the record).
