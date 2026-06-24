# Bastion Send — end-to-end encrypted notes between users (design doc, v0.2)

> Status: **audit-incorporated, ready for P0**. Reviewed by Berbarus, Grok and
> Codex (cryptographic design review). All three returned *conditional GO* with
> the same P0-blocking fixes; this v0.2 folds them in. Changelog vs v0.1 at the
> end. Implement P0 (crypto-core + tests, no server/UI) against this spec.

## 1. Goal

Let a Bastion user send a **private note** to another Bastion user such that
**only the chosen recipient can decrypt it**, end-to-end, server never sees
plaintext. Optional **passphrase** as a true second factor. Reuses the audited
core (Argon2id, HKDF-SHA256, XChaCha20-Poly1305, zero-knowledge vault); adds
X25519 (encryption) + Ed25519 (optional signatures).

### Non-goals (v0.1)
Not real-time chat; not a metadata-hiding network; 1→1 only. Server-anonymous
("whistleblower") send with an **unauthenticated** POST path is explicitly
**v0.2** — see §8. Endpoint compromise is out of scope (same as the vault).

## 2. Threat model
Defend against: **malicious/breached server** (must not read notes, recover
private keys, MITM via a forged directory key, replay, or forge sender auth),
network attacker, and other users (no mailbox enumeration, no reading others'
notes). Out of scope: endpoint malware, and traffic-analysis/metadata beyond the
cheap mitigations in §9.

Trust hinges on the recipient's **public key being authentic** — guaranteed only
by out-of-band **safety-number** verification (§6). Unverified = TOFU with the
server as a *trusted* key directory (lower assurance; must be visibly labeled).

## 3. Identity keys
At first use, the client generates **two** keypairs:
- **X25519** (`enc`) — encryption (sealed-box recipient key).
- **Ed25519** (`sig`) — optional sender authentication (§7).

Kept **independent** (never derive one from the other's seed). Stored in a
**versioned keyring inside the vault** (encrypted under the vault key; server
never sees private keys; syncs across devices). Public keys + `key_version` are
published to the server directory. Old `enc` private keys are **never deleted**
(needed to open in-flight notes — §key-rotation). Randomness via the same
`OsRng`/`getrandom(js)` path as core; secrets `zeroize` on drop.

## 4. Bastion ID
**128-bit random opaque ID**, Crockford base32, grouped for display
(e.g. `BSTN-4K2P-9XQ7-J3MN-…`). Not sequential, not enumerable (2¹²⁸).

- Directory resolution `ID → {enc_pub, sig_pub, key_version}` is **exact-match
  only** (no prefix search), **requires an authenticated session**, and is
  **rate-limited** per account. (Unauthenticated lookup for the anonymous-send
  use case is **v0.2**.)
- Don't expose `prev_key_fingerprint` or precise `created_at` to lookups (leaks
  rotation history/linkage); coarse timestamps only.
- Optional human handles (`alice#4821`) may come later but go through the same
  authed + rate-limited path and **never** bypass safety-number verification;
  crypto addressing always uses the opaque ID + the verified key.

## 5. Encryption construction (FINAL)

Envelope encryption: a random per-message **CEK** encrypts the body; CEK is
wrapped to the recipient (X25519) with the optional passphrase **folded into the
wrap KDF** (not a separate outer layer — see rationale). Everything is bound to
one **canonical protected header**.

### 5.1 Canonical protected header (bound into every AAD + the signature)
```
H = {
  v: 1, type: "send",
  message_id,            // random 128-bit, replay protection
  recipient_id,
  recipient_enc_pub, recipient_key_version,
  eph_pub,               // ephemeral X25519 public
  body_nonce, wrap_nonce,
  pw: { argon2_params, salt } | null,
  padding_bucket,
  // NOTE: sender_id / sig are NOT here — they live inside the encrypted body (§7)
}
header_bytes = canonical_serialize(H)   // deterministic encoding
```

### 5.2 Send
```
message_id = random16
CEK        = random32

# ---- body (sealed-sender-lite: sender identity lives INSIDE the ciphertext) ----
if signed:
    transcript = SHA256( "pm:v1:send/sig" || header_bytes || sender_id
                         || recipient_id || recipient_enc_pub || eph_pub
                         || message_id )
    inner = { plaintext, sender_id, sig = Ed25519.sign(sig_priv, transcript) }
else:
    inner = { plaintext }
inner = pad_to_bucket(inner)                         # size-bucket padding (§9)
body  = XChaCha20Poly1305(CEK, body_nonce, inner, aad = "pm:v1:send/body" || header_bytes)

# ---- wrap CEK to recipient, passphrase FOLDED INTO THE KDF ----
eph_priv, eph_pub = X25519 ephemeral keypair
shared            = X25519(eph_priv, recipient_enc_pub)
REQUIRE shared is contributory / not all-zero          # MANDATORY (§10)
pw_material       = passphrase ? Argon2id(passphrase, salt, argon2_params) : ""   # 32B or empty
wrap_key          = HKDF-SHA256(ikm  = shared || pw_material,
                                salt = eph_pub || recipient_enc_pub,
                                info = "pm:v1:send/recipient")
cek_commit        = HKDF-SHA256(ikm = wrap_key, info = "pm:v1:send/commit")   # key-commitment
wrapped_cek       = XChaCha20Poly1305(wrap_key, wrap_nonce, CEK, aad = "pm:v1:send/wrap" || header_bytes)

blob = { ...H, wrapped_cek, cek_commit, body, expires_at?, read_once? }
```

### 5.3 Open
```
require known v/type
if blob.pw: REQUIRE validate_for_unlock(blob.pw.argon2_params)   # anti-DoS ceiling (1 GiB/20/16)
enc_priv = keyring[blob.recipient_key_version]                   # fail if absent
shared   = X25519(enc_priv, blob.eph_pub); REQUIRE contributory / not all-zero
pw_mat   = passphrase ? Argon2id(passphrase, blob.pw.salt, blob.pw.argon2_params) : ""
wrap_key = HKDF-SHA256(shared || pw_mat, salt = blob.eph_pub || my_enc_pub, info = "pm:v1:send/recipient")
REQUIRE  cek_commit == HKDF-SHA256(wrap_key, info = "pm:v1:send/commit")
CEK      = AEAD_open(wrap_key, wrapped_cek, aad = "pm:v1:send/wrap" || header_bytes)   # opaque fail
inner    = unpad(AEAD_open(CEK, body, aad = "pm:v1:send/body" || header_bytes))
if inner.sig:
    REQUIRE Ed25519.verify_strict(sender_sig_pub, transcript, inner.sig)
    AND sender_sig_pub == the safety-number-verified key for inner.sender_id
drop if message_id already in seen-set
```

### 5.4 Why these choices (audit consensus + the one tie-break)
- **X25519 + HKDF(salt = eph_pub‖recip_pub) + AEAD** = age's recipient stanza
  (the reference all three endorsed). `recip_pub` in the salt is the
  **anti-redirection** binding: the server can't re-point a blob at another
  mailbox (the CEK won't unwrap).
- **Passphrase folded into the wrap KDF (not an outer AEAD layer).** Tie-break:
  Grok/Codex proposed nesting `pw(recip(CEK))` (passphrase outer); Berbarus
  proposed folding — **we adopt folding**. With passphrase *outer*, anyone
  holding the blob (the server) can run an **offline dictionary attack** on the
  (low-entropy, out-of-band) passphrase — the outer AEAD is a verification
  oracle, throttled only by Argon2id. With folding, deriving `wrap_key` requires
  `shared`, i.e. the recipient's **private key**, so the server cannot even
  *attempt* passphrase guesses. This is the whole point of a second factor.
  ("Two independent wraps of CEK" is **rejected** outright — it's OR, not AND:
  the recipient key alone recovers CEK, silently deleting the second factor.)
- **CEK key-commitment** (`cek_commit`) closes the partitioning-oracle class
  (Poly1305 isn't key-committing) even for an attacker who holds the key.
- **AEAD failure is opaque** (wrong key vs wrong passphrase vs tamper
  indistinguishable), consistent with the vault.

## 6. Key verification — safety number (mandatory for the "military" claim)
Per-user fingerprint binds **all** identity material (Berbarus/Codex caught that
v0.1 hashed only `enc_pub`, letting the server swap `sig_pub` and forge sender
auth while the number still matched):
```
fp(user) = iterate_5200( SHA-512( "pm:v1:send/fp/v1" || bastion_id
                                  || enc_pub || sig_pub || key_version ) )  -> 30 digits
safety_number = sort(fp(A), fp(B)) joined  -> 60 digits + QR
```
Iteration (Signal-style) taxes short-compare grinding. Users compare it
out-of-band once → contact becomes **verified** and pinned (stored in the
vault). Any later key change ⇒ **loud warning + forced re-verification before
send**. UI must make **verified ✓ / unverified / key-changed ⚠** unmissable.
TOFU is the default only with that visibly-distinct unverified state.

## 7. Sender authenticity — sign-then-encrypt (unanimous)
- `{sender_id, sig}` go **inside** the AEAD body (under CEK), never in
  cleartext → the **server never learns the sender even in signed mode**
  (sealed-sender-lite, a cheap win).
- The signed `transcript` binds `sender_id` + `recipient_id` +
  `recipient_enc_pub` + `eph_pub` + `message_id` (defeats surreptitious
  forwarding / unknown-key-share / identity-misbinding — Davis).
- **Signed by default**, with an explicit **"send anonymously"** toggle.
- Honest wording: in v0.1 "anonymous" = **anonymous to the recipient**; the
  authenticated POST (§8) means the server still links the upload to the
  sender's session. True server-anonymity is v0.2.

## 8. Delivery / abuse controls
- `POST /send` (**authenticated** in v0.1) → server stores the opaque blob in
  the recipient's inbox keyed by `recipient_id`.
- `GET /inbox` (authenticated) → pull blobs → decrypt locally.
- **Required controls before launch:** `message_id` uniqueness + per-recipient
  dedupe; per-sender & per-recipient **rate limits**; **inbox quota** (bounded
  count, drop-oldest or reject); small **note size cap** (e.g. 64 KiB–1 MiB, far
  below the core's ~8 MiB); best-effort **read-once** delete + `expires_at`;
  recipient **contacts-only** toggle (quarantine/reject unverified senders).
- **v0.2:** optional unauthenticated `POST /send` for true anonymous sends, gated
  by proof-of-work + stricter rate limits.

## 9. Metadata (honest)
Server learns: which IDs have mailboxes, that a blob targets ID X, **bucketed**
size, upload/fetch timing, and (v0.1, authed POST) which account uploaded.
Does **not** learn: content, CEK, private keys, or the cryptographic sender
(sender is inside the body). Cheap v0.1 wins applied: **size-bucket padding**
(256 B / 1 / 4 / 16 / 64 KiB), sender-inside-body, coarse server timestamps,
minimal logged upload metadata. State this plainly in the UI.

## 10. Libraries + mandatory validation
- `x25519-dalek` v2.x: `EphemeralSecret` per message, `StaticSecret` for the
  vault identity (both clamp internally). **Mandatory both sides:** reject a
  non-contributory / all-zero shared secret (`was_contributory()` /
  `shared == [0;32]`) — `recip_pub` (untrusted directory) or `eph_pub`
  (untrusted blob) could be a low-order point yielding a server-known zero shared.
- `ed25519-dalek` v2.x: **`verify_strict`** only (rejects small-order A,
  non-canonical S → no malleability/cofactor surprises); validate `sig_pub`
  through the verifying-key constructor.
- Pin versions; `zeroize` secrets; route randomness through core's CSPRNG path;
  gate CI on a `cargo audit` / RUSTSEC check; include age X25519 KATs + a
  zero-shared-rejection known-answer test.

## 11. Key rotation / multi-device
- `key_version: u32` (monotonic) in the directory **and** every blob; `open()`
  selects the private key by `recipient_key_version`.
- **Persistent versioned keyring in the vault; never delete old `enc` private
  keys** → in-flight notes stay decryptable; new devices inherit it via vault
  sync (zero special handling). Identity is per-account, not per-device.
- Explicit **"rotate identity keys"** action: new pair, bump `key_version`,
  publish (CAS-style update to avoid races), keep old privs, **force
  re-verification** (safety number changes → contacts warned). Lost device =
  endpoint compromise (out of scope) → user rotates from a good device.
- Optional (P2+): a rotation certificate `Ed25519.sign(old_sig_priv,
  new_enc_pub‖new_sig_pub‖key_version)` for continuity — surfaced, not
  auto-trusted.

## 12. Replay / domain separation
- **Replay:** `message_id` bound into header/AAD/transcript; recipient keeps a
  bounded **seen-set** and drops dups; server dedupes by `message_id` +
  best-effort read-once.
- **Domain separation:** all Send labels live under the core's `pm:v1:send/*`
  family (`…/recipient`, `…/wrap`, `…/body`, `…/sig`, `…/commit`, `…/fp/v1`) —
  *not* a second `bastion-send/*` scheme (two schemes invite mistakes). Every
  Send AEAD/transcript carries `type="send"` + `v`. A Send blob cannot validate
  as a vault item or manifest (different keys + disjoint AAD); add a
  cross-family test asserting the namespaces are disjoint.

## 13. §11 open-question rulings (resolved)
1. **Passphrase**: fold into the recipient HKDF `ikm` (single AEAD) + CEK
   key-commitment; reject independent-wrap (OR) and passphrase-outer (offline
   oracle). Argon2id = vault default (64 MiB/3/4), params in blob,
   ceiling-validated on open.
2. **Bastion ID**: 128-bit opaque; directory resolution authed + exact-match +
   rate-limited.
3. **Safety number**: iterate over `bastion_id‖enc_pub‖sig_pub‖key_version`
   (both keys, not just enc); 60-digit + QR; verified/unverified/changed UI.
4. **Anonymous + read-once**: sign-then-encrypt (sender hidden from server) +
   size-bucket padding; v0.1 authed POST ⇒ anon = anon-to-recipient only;
   server-anon = v0.2.
5. **Rotation/multi-device**: `key_version` + persistent versioned keyring,
   never delete old enc privs; vault sync carries it.
6. **Domain separation**: unified `pm:v1:send/*` + `type`/`v` in every
   AAD/transcript; cross-family test.
7. **Replay**: `message_id` + recipient seen-set + server dedupe + read-once.
8. **DoS**: authed POST + rate limits + inbox quota + size cap + contacts-only;
   PoW only if/when an unauth path is added (v0.2).

## 14. Go status & phasing
**GO for P0**, conditional on building exactly to this v0.2 spec. P0-blocking
items (all incorporated above): folded-passphrase + CEK commitment;
contributory/zero-shared rejection + `verify_strict`; safety number over both
keys (iterated); sign-then-encrypt with full transcript binding; canonical
header bound into every AAD; Argon2 ceiling-validation on open; `key_version` +
persistent keyring; `message_id` + replay + abuse controls; unified
`pm:v1:send/*` namespace; pinned crate versions + validation/KATs.

- **P0**: crypto-core — X25519 seal/open, folded passphrase, CEK commitment,
  safety number, all bindings + KATs/known-answer tests. No server/UI.
- **P1**: crypto-wasm bindings + identity keyring stored in the vault.
- **P2**: server directory + inbox (authed, rate-limited, quotas, read-once).
- **P3**: extension/web UI — Send, inbox, verify-contact (safety number), signed
  vs anonymous, optional passphrase, read-once/expiry.
- **v0.2**: unauthenticated/anonymous-to-server send (PoW-gated), handles,
  rotation certificates.

## Changelog v0.1 → v0.2 (audit fixes)
- Passphrase: **fold into wrap KDF** (was: undecided / "two independent wraps")
  + add **CEK key-commitment**. Rejected passphrase-outer (offline oracle).
- Safety number now covers **enc_pub + sig_pub + bastion_id + key_version**,
  **iterated** (was: SHA-256 of enc_pub only — server could swap sig_pub).
- **Sign-then-encrypt**: sender id/sig moved **inside** the body (was: cleartext
  → leaked sender to server); transcript now binds sender_id + recipient_enc_pub.
- Mandatory **contributory/zero-shared rejection** + **verify_strict**.
- Canonical **protected header** bound into every AEAD AAD + the transcript.
- **Argon2 ceiling-validation** of attacker-supplied params on open (anti-DoS).
- **key_version + persistent keyring**; defined rotation/multi-device.
- **message_id + replay** protection; **authed POST + rate/size/quota** controls.
- Bastion ID 80→**128-bit**; directory authed + rate-limited.
- Unified domain labels under **`pm:v1:send/*`**; size-bucket **padding**;
  corrected metadata/anonymity wording.
