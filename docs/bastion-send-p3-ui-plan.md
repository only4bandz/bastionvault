# Bastion Send — P3 UI/UX + Implementation Plan (v1)

**Status**: Planning artifact. Backend + crypto-wasm complete and audited (P0-P2 done on main). This is the buildable spec for P3 frontend surfaces only. Do not write feature code from this until reviewed; use it as the implementation contract.

**Scope reminder (from design doc)**: End-to-end encrypted 1:1 notes. Zero-knowledge: server sees only opaque blobs + published PublicIdentity. All crypto in WASM `Account`. UI never renders unverified senders as trusted.

**Two surfaces, reuse design system**:
- Chrome extension popup (360×600, vanilla JS + CSS, strict CSP: no inline script/eval, no external). Screen swaps via `innerHTML`. Shares `tokens.css`.
- Web app (React + TS, sidebar shell). Shares tokens via `app/src/index.css` (mirror of tokens).

**Key existing primitives** (use exactly):
- WASM on `Account` (string/JSON API):
  - `send_identity_item_id()` → `"bastion:send-identity"`
  - `create_send_identity()` → encrypted vault-item blob JSON (persist via normal PUT item)
  - `load_send_identity(blobJson)`
  - `has_send_identity` (getter)
  - `send_identity_public()` → PublicIdentity JSON
  - `send_seal(plaintext, recipient_id, recipient_public_json, passphrase?, sender_id?)` → SendBlob JSON (contains `recipient_id`, `message_id`, `...`)
  - `send_open(blobJson, passphrase?, verify_sender_json?)` → `{ plaintext, sender: { state: "anonymous"|"unverified"|"verified", id: string|null } }`
  - free: `send_safety_number(idA, pubA_json, idB, pubB_json)` → 60-digit string
- Server (bearer-auth):
  - `PUT /send/identity` (body=PublicIdentity) → `{ bastion_id }`
  - `GET /send/whoami` → `{ bastion_id, public }` (404 if none)
  - `GET /send/directory/:bastion_id` → PublicIdentity (404 unknown, rate-limited)
  - `POST /send` `{ recipient_id, message_id, blob: SendBlob, expires_at? }` → 204 / 409 dup / 413 / 429 / 404
  - `GET /send/inbox` → `[{ message_id, blob, created_at, expires_at }]`
  - `DELETE /send/inbox/:message_id` (204)
- Vault items: Send identity lives as reserved encrypted vault item (synced). Contacts recommended as second reserved item.
- Auto-lock already drops identity (WASM `lock()` clears it).
- Design tokens: `--accent`, `--ok` (green), `--warn`, `--danger`, radii, Inter + JetBrains Mono, ease, dark/light via `[data-theme=light]`. Existing patterns: `.pill`, `.toast`, `.row-copy`, `.btn`, `.input`, `.card-section`, `.empty`, modals, icon-btns, flashCheck/copyText in ext.

**Non-goals for P3**: real-time, threading beyond "reply prefill", server-anon send (v0.2), push notifs, abuse block UI beyond "don't add contact".

---

## 0. Build rules — audit-confirmed (these GOVERN §A–H; §I has the detail)

> Consolidated from the Codex + code-grounded review. Where §A–H conflicts with
> a rule below, the rule wins. Read these first; they are correctness/security.

- **BR1 — Extension Send logic is background-owned.** The popup is a thin view
  that messages `background.js`; the worker owns the WASM `Account`, the token,
  and all crypto/identity/inbox calls. The new `SEND_*`/`CONTACTS_*` message
  verbs MUST NOT be added to `CONTENT_ALLOWED` — Send is extension-page-only, so
  no content script on a web page can reach a user's inbox/identity/contacts. (§I.5)
- **BR2 — Hide reserved items.** Exclude `id.startsWith("bastion:send-")`
  wherever the vault list is built on BOTH surfaces (background `toMeta`/`LIST`
  and `app/src/App.tsx` `loadItems`) — else identity/contacts show as junk rows.
  Do this first. (§I.1)
- **BR3 — Enable Send safely (multi-device).** On unlock, if the reserved
  `send_identity_item_id()` item exists → `load_send_identity`. On "Enable",
  call `GET /send/whoami` FIRST: only `create_send_identity()` when whoami is
  404; if it returns a bastion_id but this device lacks the item, do NOT create
  (show "already enabled on another device"). (§I.6)
- **BR4 — Trust = a locally PINNED PublicIdentity, not `key_version`.** Pin
  `sha256(canonical PublicIdentity)` at verify time. `key_version` is a display
  hint only, never the trust tripwire. (§I.2)
- **BR5 — `send_open` is two-pass for the verified upgrade.** The sender id is
  inside the ciphertext, so open once with no verifier to learn `sender.id`,
  then (only for a known verified contact) re-open with the PINNED public to
  reach `verified`; a sig failure there = key-changed → demote + red banner. (§I.3)
- **BR6 — Seal verified contacts to the PINNED key**, never a fresh
  `GET /send/directory` result; fetch the directory only to DETECT change vs the
  pin → on mismatch stop and force re-verify. Unverified/TOFU may seal to the
  directory result (labeled unverified). (§I.4)
- **BR7 — Contacts live in a second reserved vault item** `bastion:send-contacts`
  (encrypted, synced): `{ bastion_id, public (pinned), pinFp, display, verified_at,
  safety_number }`.
- **BR8 — Surface caps + map status codes.** 256 KiB blob (compose counter),
  inbox 500 / page 100, rate limits 60 (send) / 30 (sender-recipient pair) /
  120 (recipient aggregate) / 120 (lookup) per min; 404→"no/expired",
  409→"already submitted", 413→"too large", 429→
  disambiguate "sending too fast" vs "recipient inbox full". (§I.7)
- **BR9 — Clear on lock.** Opened plaintext, drafts, inbox cache, verify modals,
  and the Send identity all drop on auto-lock (identity already cleared in WASM).

**P3a MVP = extension only**: Enable Send (whoami-guarded) + Bastion ID card +
Contacts (add by id + manual numeric verify) + Compose (signed/anon + optional
passphrase) + Inbox (manual refresh, open, trust badge, delete-after-read) +
reserved-item filtering (BR2). Then **P3b** web parity (reuse a shared JS Send
client), **P3c** QR + polish/delights.

---

## A. End-to-End Flows (with states)

### 1. First-run "Enable Send" / Publish Identity + Show Bastion ID
**Pre**: Vault unlocked, account ready. No Send identity in vault or memory.
1. User reaches Send surface (see B).
2. Prominent "Enable Bastion Send" or "Create your Send identity" primary action (big btn, shield icon).
3. On click (optimistic):
   - Call `account.create_send_identity()` → blobJson.
   - `api.putItem(token, send_identity_item_id(), JSON.parse(blobJson))` (normal vault path; optimistic UI "enabled").
   - `const pub = JSON.parse(account.send_identity_public())`.
   - `PUT /send/identity` body=pub → `{ bastion_id }`.
   - Store `bastionId` + `myPublic` (in-memory + re-derive on reload).
4. Transition to "Your Bastion ID" success state:
   - Large mono display of bastion_id (grouped, e.g. `BSTN-4K2P-9XQ7-J3MN-QR8T-VL2X` — format client-side; Crockford base32 26 chars).
   - Buttons: Copy ID, Show QR (canvas), "Done".
   - Subtext: "Share this ID so others can send you notes. It never changes."
5. Edge: if PUT /send/identity fails (429 etc.) still keep local identity; surface "Publish later" and retry on next Send enter. Identity item is the source of truth for "enabled".

**States**: disabled → creating (spinner on btn) → enabled (show ID, toast "Send enabled").

**Auto on future unlocks**: After `getVault` + `loadItems`, if `items[send_identity_item_id()]` exists:
- `account.load_send_identity(JSON.stringify(items[...]))`
- Then silently `GET /send/whoami` (or PUT idempotent) to (re)learn bastion_id. If 404, re-publish from memory identity.

### 2. Add/Verify a Contact (safety number critical path)
1. "Add contact" (or from compose recipient picker "Add new...").
2. Input: Bastion ID (paste, or free text; accept with/without separators; normalize on resolve).
3. "Resolve" → `GET /send/directory/${id}`.
   - 404: "Unknown recipient. They must enable Send and share their ID."
   - OK: receive `PublicIdentity` JSON.
4. Compute `safety = send_safety_number(myBastionId, myPubJson, recipId, recipPubJson)`.
5. **Safety Number Screen** (unmissable, calm, focused):
   - Header: "Verify safety number with <ID or name if later handles>"
   - Huge mono 60-digit, grouped every 5 (`12345 67890 ...` ×12), high contrast, copyable.
   - QR code (same data) for scan/compare (optional out-of-band).
   - Instructions (exact copy later): "Compare this number out-of-band (in person, call, or Signal). Do not trust if it does not match exactly."
   - Checkbox: "I have compared the full 60 digits and they match."
   - Primary: "Mark as verified" (disabled until checkbox). Stores locally.
6. On mark verified:
   - Persist contact: `{ [recipId]: { public: recipPub, verified: true, verifiedAt: Date.now(), safetyNumber: safety, keyVersion: recipPub.key_version } }` as encrypted vault item `bastion:send-contacts`.
   - Encrypt + `putItem` (optimistic).
   - Mark contact "verified ✓" in lists.
7. Key change handling (see below in E).

**Storage decision (opinionated)**: Contacts live in a second reserved vault item `"bastion:send-contacts"` (encrypted JSON object). Benefits: zero-knowledge, multi-device, survives reinstall via vault sync. Load on unlock same as identity. In-memory Map<id, Contact> in session state.

Alternative rejected: chrome.storage.local or React state only (no sync).

### 3. Compose & Send
1. From Send surface: "+" / "New note".
2. Form:
   - Recipient: autocomplete from verified contacts (name/id) + free-text "Enter Bastion ID" mode. On free-text resolve on blur or explicit "Lookup".
   - If recipient not verified: warning banner "Unverified recipient — messages are encrypted but sender authenticity cannot be confirmed. Compare safety number first."
   - Note body: `<textarea>` (plain text only; 256KiB server cap — UI soft-limit ~200KiB with counter).
   - Optional passphrase: toggle + password input ("Recipient must know this passphrase too. This is a true second factor.").
   - Sender mode: segmented "Sign with my identity (recommended)" / "Send anonymously". Default signed. Explanation on hover/tap: "Signed: recipient can verify it came from you if they have verified your keys. Anonymous: hides your identity from recipient."
   - Expiry: select (Never, 1 hour, 1 day, 7 days) → computes `expires_at` (unix secs) or null.
   - Read-once: checkbox "Delete after recipient reads" (maps to `read_once`? Server currently uses best-effort via delete after GET, but blob can carry flag; for now send as hint in UI, actual delete is explicit or on read).
3. "Send" (primary):
   - If no identity: error.
   - If signed mode is selected but `whoami` cannot confirm the sender ID: stop
     and show an error. Never silently send the message anonymously.
   - Lookup/resolve recipient if needed.
   - `const sealed = account.send_seal(plaintext, recipId, recipPubJson, passphrase || undefined, signed ? myId : undefined)`.
   - Parse `const b = JSON.parse(sealed); const { message_id, recipient_id } = b;`
   - `POST /send { recipient_id, message_id, blob: b, expires_at }`.
   - On 204: success toast "Sent. Recipient will see it in their inbox." Clear form or offer "Send another". (Optimistic: show in "Sent" local history if desired, but inbox is source.)
4. Errors inline under form (see error taxonomy).

### 4. Inbox (list, open, trust state, reply, delete-after-read)
1. On entering Send inbox surface: auto `GET /send/inbox` (with loading).
2. List: reverse chrono (newest?), each row:
   - Left: trust badge (see B).
   - Middle: short preview of plaintext? (No: never decrypt until open; show "Encrypted note" + created_at + expires badge if any. Sender ID if present from prior? Use sender state on list by peeking? No — list stays opaque until open. Show sender_id if known from blob? Blobs have no sender in clear. List rows are minimal: time, "New note", expires chip.)
   - Better: list shows only metadata + "Open". On open, decrypt + full view.
3. Open message:
   - Fetch blob from list.
   - If passphrase flag in blob: prompt passphrase first (modal).
   - `const opened = JSON.parse( account.send_open(JSON.stringify(blob), pass, contactPubForSenderIfAny ) )`.
   - Render: full plaintext (mono or wrapped? readable prose area).
   - **Prominent trust banner** at top of message:
     - verified: green ✓ "Verified from <id>" (or "You" if self?).
     - unverified: amber ⚠ "Unverified sender. Safety number not compared."
     - anonymous: gray "Sent anonymously".
   - If sender id present and contact not verified: "Add & verify this sender" quick link.
   - Actions: Reply (prefill compose with recipient=sender_id, body=""), Delete (DELETE /inbox/:message_id; optimistic remove + toast "Deleted (read-once)"), Copy plaintext, Close.
4. After open: encourage delete. Server read-once is best-effort + client DELETE.
5. Empty: "No messages. Notes disappear after reading."
6. Manual "Refresh" button (and auto on focus/enter if >30s stale). No aggressive polling (rate limits).

### 5. Key-state & Transport Edge Cases
- Recipient unknown/unpublished: resolve 404 or post 404 → clear "Unknown Bastion ID. Ask the recipient to enable Send."
- Key changed since verify: when resolving or before send, re-fetch `/directory` and compare key_version vs stored contact. If mismatch: loud inline warning + "Key rotated. Re-verify safety number before trusting signed messages." Disable auto-trust; force re-verify flow to update stored pub.
- Vault locked: Send surfaces show "Unlock to use Send" or redirect to unlock (existing pattern).
- Offline / network: ApiError(0) → "Cannot reach server. Check connection."
- Rate-limited: 429 → "Rate limited. Please wait a minute."
- Inbox full (recipient): 429 specific "Recipient's inbox is full."
- Duplicate: 409 on send → treat as success (idempotent) or "Already sent this exact note."
- Blob too large: 413.
- No Send identity on send attempt: "Enable Send first."
- Identity item missing on load but we think we have one: treat as locked-for-send.

---

## B. Screen-by-Screen UX (Both Surfaces)

### Extension Popup (vanilla, 360×600)

**Placement**: New bottom-bar entry. Current bar (gear | gen | spacer | lock). Proposal:
- Bar becomes: `<gear settings> | <vault icon> Vault | <send icon> Send | <gen> | <lock>`
- Or simpler (less crowding): keep existing 3, add Send as 4th action that replaces main content. On Send screen the bar can show "← Vault" on left or use existing back pattern.
- Clicking Send icon calls `showSend()` (full replace like `showGenerator`).

**Send Screen Structure** (prose wireframe):

```
┌────────────────────────────────────┐
│ ← Back     BASTION SEND     [ID]   │  ← small header; [ID] = abbreviated bastion or "setup"
├────────────────────────────────────┤
│ Your Bastion ID                    │
│ BSTN-XXXX-XXXX-XXXX...  [copy][qr] │  ← only if enabled; else hidden
├────────────────────────────────────┤
│ [ Inbox (3) ]  [ New ]  [ Contacts ]│ ← segmented tabs (simple divs + state)
├────────────────────────────────────┤
│                                    │
│  <inbox list or form or contacts>  │  ← .scroll area, reuse .empty
│                                    │
└────────────────────────────────────┘
  [ bottom bar always visible: actions ]
```

**Detailed sub-screens**:

- **Disabled / Enable state** (first visit):
  - Centered hero shield + "End-to-end encrypted notes"
  - "Enable Send" large primary `.btn.btn-primary`.
  - Small print: "Creates keys stored in your vault. Zero-knowledge."
  - On success: auto show ID card + "Inbox empty. Send your first note."

- **Inbox list**:
  - Header row "Inbox" + refresh icon.
  - Rows (reuse .row): time | "Encrypted note" | trust chip (tiny) | chevron or open action.
  - If loading: skeleton or "Loading…".
  - Empty: nice empty state with "Send a note to get started."

- **Open message** (like .detail):
  - dtop: back + "Delete" danger.
  - Trust banner (full width, colored bg): ✓ Verified / ⚠ Unverified / ? Anonymous. Include sender id if present.
  - Plaintext block (pre-wrap or prose, selectable, copy button).
  - Bottom actions: Reply | Copy | Delete (read-once).

- **Compose** (scrollable form in .dscroll):
  - Recipient picker (select or input + lookup btn).
  - Warning if unverified.
  - Large textarea (rows ~8).
  - Passphrase row (checkbox reveal + input).
  - Sender toggle (two pills).
  - Options row: expiry select + read-once checkbox.
  - Send btn (disabled until recip + body).
  - Size counter "124 / ~200 KiB".

- **Contacts**:
  - List of verified (only; unverified are implicit).
  - Each: ID (mono) + ✓ + "Safety number" btn (re-show) + "Remove".
  - + Add button → resolve + safety flow (modal or full replace view).

**Empty / error states**: Reuse existing `.empty`, `.callout` (danger tint for errors).

**Trust badges (unmissable)**:
- Verified: `<span class="trust trust-ok">✓ Verified</span>` green.
- Unverified: `<span class="trust trust-warn">⚠ Unverified</span>`.
- Anonymous: `<span class="trust trust-anon">? Anonymous</span>`.
  Style: pill-like, bold, placed before any sender id or note content.

**Icons**: Add to ICON map:
- send: share-like or envelope.
- shieldCheck, alertTriangle, userQuestion etc. (inline svgs, reuse existing pattern).

**CSP**: All dynamic via createElement / innerHTML safe patterns already used (esc). No new eval. For QR use canvas 2d (allowed).

### Web App (React + TS, sidebar shell)

**Placement**: Sidebar "Shared" nav-item. Rename label to **"Send"** (opinionated; "Shared" was placeholder). Icon keep or enhance IcShared → send-oriented.

On click `setNav("send")` (extend the Nav union).

Main content area hosts `<SendView ... />` (new component).

**SendView layout** (grid-ish like vault):
- Topbar-like or page-head: "Send" + "New note" primary btn (right).
- Optional sub: Your ID banner (collapsible pill) with copy/QR.
- Two-column or tabbed:
  - Left/main: Inbox list (table or card rows) + search (filter local after fetch).
  - Or stacked for simplicity: Inbox section (list), floating or separate Compose card/panel.
- Better opinionated: Split view or mode:
  - Primary pane: Inbox (list + selected open preview inline or modal).
  - Secondary column or drawer: "Contacts" list (add + verify links).
  - Compose as modal (reuse .overlay/.modal patterns) or full replace content when composing.
- Detail open: use existing modal pattern or new "MessageModal" for the decrypted view + trust banner + reply.

**Wireframe (prose)**:
```
Sidebar          |  Main (Send)
-----------------|--------------------------------
...              |  Send
Vault            |  ┌──────────────────────────────┐
Send (active)    |  │ Your ID: BSTN-... [copy][qr] │
Trash            |  └──────────────────────────────┘
                 |  Inbox (3)               [Refresh]
                 |  ┌ row1  10m ago  ✓  [Open]    │
                 |  └──────────────────────────────┘
                 |  [ + New note ]
```

**Components (new, in app/src/screens/Send.tsx or components/Send/*)**:
- `SendView` (orchestrator)
- `BastionIdCard`
- `InboxList`
- `MessageView` (or inside modal)
- `ComposeForm`
- `AddContactModal` / `SafetyCompare` (the 60-digit + QR + confirm)
- `TrustBadge` (stateless, takes SenderState)
- `RecipientPicker`

Reuse: Brand, icons (add IcSend if needed), toast from parent, Account + token passed or via context later.

**Empty states**: "No notes yet." "Enable Send to receive." Use existing empty with custom icon/text.

**Loading**: Spinner on actions or full "Fetching inbox...".

**Responsive in shell**: Fits existing 248px sidebar + content padding.

---

## C. Component + State Architecture

### Shared (recommended factor)
Create `lib/send-client.js` (vanilla, importable) + `lib/send.ts` (web, or single .ts compiled for both if build allows). Pure functions + thin class wrapper around Account + Api.

But keep minimal: most logic lives in the surfaces. Extract:
- `normalizeBastionId(s: string): string`
- `formatSafetyNumber(s: string): grouped string`
- `formatBastionIdForDisplay(id: string): string`
- Error mapping helper.

### Extension (popup.js + background.js)
**Popup state**: local module vars (currentSendState, myBastionId, contactsMap, inbox, etc.). No persistence beyond vault.
- `showSend()` renders full view.
- New messages to bg: `SEND_ENABLE`, `SEND_WHOAMI`, `SEND_RESOLVE`, `SEND_COMPOSE`, `SEND_INBOX`, `SEND_OPEN`, `SEND_VERIFY_CONTACT`, `SEND_REFRESH`, etc.
- Background augments session: `sendIdentityLoaded: bool`, `bastionId: string|null`, `contacts: Map<string, Contact>`, `inboxCache`.

**On unlock path (bg doUnlock + rehydrate)**:
- After building items Map:
  - const id = send_identity_item_id()
  - if (items.has(id)) account.load_send_identity( JSON.stringify( encryptBlobFor(id) ) )
  - Then attempt whoami/publish.

Contacts load similarly from reserved item.

**Optimistic**: On send, immediately reflect in local sent list if we add one; inbox refresh is explicit.

### Web (React)
- App.tsx owns `account`, `token`. Add `bastionId`, `myPublic`, `contacts` (Map), `sendEnabled`.
- On unlock success (after setItems): hook `loadSendIdentityIfPresent(account, vault.items)`.
- Then `ensureSendIdentityPublished()`.
- Pass down to `Vault` (or lift SendView to top level) or new top-level phase/route. For P3 keep inside vault phase with nav.
- Send-specific state local to `SendView` or lifted: `inbox`, `selectedMessage`, `composeOpen`.
- Mutations: same optimistic pattern as upsert/remove, but for contacts + separate send APIs (new methods on api.ts).

**Api.ts / api.js extensions** (exact):
```ts
// send
publishSendIdentity: (token, pub) => req("PUT", "/send/identity", token, pub) → {bastion_id}
getWhoami: (token) => ...
getDirectory: (token, bastionId) => ...
postSend: (token, {recipient_id, message_id, blob, expires_at?})
getInbox: (token) => ...
deleteInbox: (token, message_id)
```

**Vault item reserved ids**:
- `send_identity_item_id()` from WASM
- `const SEND_CONTACTS_ITEM_ID = "bastion:send-contacts"`

**Local vs synced**:
- Synced: identity blob, contacts blob (vault items).
- Ephemeral/in-memory only: current inbox list, resolved temp recipients, form state.
- Bastion ID: learn once, cache in session (rehydrate path re-fetches whoami).

**Polling vs manual**: Manual + on-enter refresh. Add a "lastInboxFetch" timestamp; auto-refresh if stale > 45s on screen focus.

---

## D. Exact Wiring (Call Sequences)

### Enable / Bootstrap on Unlock
1. unlock flow completes, vault fetched.
2. `const sid = send_identity_item_id(); const blob = vault.items[sid];`
3. if (blob) `account.load_send_identity( JSON.stringify(blob) );`
4. if (account.has_send_identity) {
     try { const w = await api.getWhoami(token); myBastionId = w.bastion_id; }
     catch (404) { await publish(); }
   }

### Publish
`pubJson = account.send_identity_public()`
`{ bastion_id } = await api.publish... (JSON.parse(pubJson))`

### Compose + Post
```js
const recipPub = ... // from contacts or directory
const sealed = account.send_seal(plain, recipId, JSON.stringify(recipPub), pw || null, signed ? myId : null)
const b = JSON.parse(sealed)
await api.postSend(token, {
  recipient_id: b.recipient_id,
  message_id: b.message_id,
  blob: b,
  expires_at: expiry ? Math.floor(Date.now()/1000) + delta : null
})
```

### Open
```js
const openedJson = account.send_open(
  JSON.stringify(inboxItem.blob),
  passphrase || null,
  contact ? JSON.stringify(contact.public) : null   // only if we have a verified entry for sender id
)
const { plaintext, sender } = JSON.parse(openedJson)
```

### Verify Contact
1. dirPub = await api.getDirectory(...)
2. safety = send_safety_number(myId, myPubStr, recipId, JSON.stringify(dirPub))
3. After user confirms: update contacts map, encrypt JSON.stringify(contactsObj), putItem(token, SEND_CONTACTS_ITEM_ID, ...)

### Inbox Refresh
`inbox = await api.getInbox(token)` (then client filters expired client-side if needed; server already purges).

---

## E. The Safety-Number / Trust UX (Security-Critical)

**Core rules**:
- Never display a sender as verified unless `Sender.Verified` from `send_open` (i.e. signature + exact pub match against stored verified contact).
- Unverified and Anonymous are always distinct and labeled.
- Verification is a deliberate out-of-band step, not skippable for the "verified" claim.

**Verification flow (approachable but not skippable)**:
- Big number (font-size ~20-24px mono, letter-spacing generous, wrap-safe grouping).
- QR (canvas, 180px or so; encode the safety string or a compact "ID1|ID2|fp").
- "Compare the entire string above. One wrong digit = do not trust."
- Explicit checkbox + enabled "Verify" only after.
- After verify: success check + stored.

**QR + numeric both**: numeric is authoritative. QR is convenience (camera compare or send via another channel).

**Key-change handling**:
- When loading a contact for send/open: `GET /directory/id` → compare key_version.
- On mismatch (or sig_pub/enc_pub differ): 
  - Banner: "⚠ Keys changed since you verified. Re-compare the safety number."
  - Button: "Re-verify now" (runs the flow again, updates stored pub).
  - Do not auto-update trust; old verified state is invalidated.

**Display of safety number**:
- Always 60 digits, 5-digit groups, spaces. Copy includes clean digits or spaced?

**Self-serve re-show**: In contacts list, "Show safety number again" (recomputes from stored pub snapshot).

---

## F. Phasing + MVP + Delights

**P3a (smallest shippable, extension-first)**:
- Extension popup only.
- Enable + publish + display your Bastion ID (copy + QR).
- Inbox list + open (decrypt + render Sender state as badge; passphrase support).
- Compose + send (to free-text ID or resolved; signed default, anon toggle, optional passphrase, expiry, read-once flag).
- Manual verify via numeric safety number (no fancy QR required first; add simple).
- Contacts stored in vault item (load/save).
- Manual refresh; basic errors mapped.
- "Send" bottom-bar entry.
- No web yet. No key-change warnings (P3b). No reply button.

**P3b**:
- Web "Shared" → full Send (rename nav).
- Parity: enable, inbox, compose, contacts.
- Add QR to both.
- Key rotation detection + re-verify warnings.
- Reply flow (prefill compose).
- Better empty/loading states, size warnings.
- Shared send-client module.

**P3c / polish**:
- "Wow" moments (see below).
- Bilingual copy (EN primary + FR).
- Accessibility pass, i18n keys.
- Contacts list polish, remove, re-verify.
- Sent history (optional local).
- Rate-limit backoff UX.

**Flagship delight moments (2–3)**:
1. **Safety number ceremony**: large, calm, copyable + QR, explicit confirmation that feels like a ritual (trustworthy not gamey). Green flash on verify.
2. **Trust banner on open**: the first thing you see inside a note is an unmissable verified/unverified/anonymous pill with clear meaning. Clicking it can re-explain or offer verify.
3. **"Sent into the vault"**: after successful POST, a short "Note sealed and delivered. It can only be opened by the recipient." with the recipient ID echoed. Feels magical because the server saw nothing.

**Shared logic to factor**:
- Pure helpers for id/safety formatting.
- Small `SendApi` wrapper (add to api.ts / api.js).
- Contact + identity load/save helpers.
- The heavy crypto is already shared via WASM.

---

## G. Risks / Open Questions + Recommendations

**Risks**:
- CSP + bundle size in extension: keep any QR code generator tiny (hand-written ~1-2k or canvas-only; no npm qr libs in popup).
- Multi-device identity: solved by vault item (this is the point). Rotation must bump key_version and force re-verifies.
- Reply threading: explicitly not supported in P3. Each note is standalone. Prefill recipient on reply is fine; no conversation grouping.
- Notifications: out of scope. User must open app/extension and refresh inbox.
- Abuse / spam: server has quotas/rate limits. UI can later add "block this ID" (local only; server contacts-only flag is future). For now document "only accept from verified contacts".
- 256KiB cap: UI must warn early on compose (char/byte counter).
- Passphrase UX: users may forget it. Make clear "this is extra; if lost, note is unrecoverable even by you."
- Key rotation race: CAS not implemented server-side for identity yet? Publish is upsert. Client should handle by publishing after create.

**Open / decisions to confirm**:
- Bastion ID display format: propose client-side grouping `XXXX-XXXX-...` (5 or 4s) with optional "BSTN-" prefix for branding. Confirm Crockford vs raw.
- Read-once: server currently best-effort delete on client action. Blob carries no enforced flag yet. Treat "read-once" as UI + client DELETE immediately after successful open.
- Expiry: server supports; client sends. Expired filtered from inbox.
- "Anonymous" wording: "Send anonymously (recipient sees no sender identity)" — note that server still knows you sent it (authenticated POST).
- Bilingual (FR): Yes. Primary strings in EN. Provide parallel FR in a copy sheet or data-i18n. For P3a keep EN; P3b add FR toggle or auto if browser `fr`. Recommend simple object of strings.
- Contacts "name": for MVP just use Bastion ID. Later alias/handle.
- QR data: encode safety number string (simple). Or compact `v1|idA|idB|fp60`.

**Accessibility**:
- All interactive have labels/titles.
- High contrast on trust badges.
- Safety number: aria labels, selectable, large target for copy.
- Keyboard: tab order in forms, escape closes modals.
- Reduce motion respected (tokens already).

**i18n note for FR user**: Plan strings with keys. Example primary:
`{ "enableSend": "Enable Send", fr: "Activer Send" }`. Start with EN for velocity.

**Other**:
- Add new icons to both `extension/popup.js` ICON and `app/src/components/icons.tsx`.
- Mirror any new CSS tokens/classes into both tokens.css + index.css.
- Tests: existing server test already good. Add light e2e smoke for flows later. For now plan focuses on manual + unit of client helpers.
- Security review of new UI paths (especially verify + sender state rendering) before ship.

---

## H. Concrete Artifacts for Implementers (Summary)

**New reserved ids**:
- identity: from WASM
- contacts: `"bastion:send-contacts"`

**State shapes (example)**:
```ts
interface Contact { public: PublicIdentity; verified: boolean; verifiedAt: number; safetyNumber?: string; keyVersion: number; }
interface SendSessionState {
  bastionId: string | null;
  myPublic: PublicIdentity | null;
  contacts: Map<string, Contact>;
  enabled: boolean;
}
```

**Status code → UX table** (implement exactly):
- 404 (directory / post recip / whoami inbox) → "Unknown..." or "Enable Send first"
- 409 duplicate → success (or "already delivered")
- 413 → "Note exceeds size limit"
- 429 (send / inbound / lookup) → "Too many attempts. Try again shortly." Specific inbox-full variant.
- 0 / network → offline message

**Screen inventory per surface**:
- Ext: unlock (existing), vault (existing), generator (existing), send (new: enable | inbox | compose | contacts | verify | open-msg)
- Web: welcome/unlock/reveal/vault (existing), send (new inside shell)

**Phased build order**:
1. P3a ext skeleton + enable + ID display + api wiring.
2. Inbox fetch + list + open (decrypt + badge).
3. Compose + full seal+post wiring + passphrase.
4. Contacts + safety verify numeric.
5. P3b web parity.
6. Polish + key change + delights + QR + errors.

**Copy seeds (exact recommended)**:
- "End-to-end encrypted notes between Bastion users."
- "Compare these 60 digits out-of-band before marking verified."
- "✓ Verified sender"
- "⚠ Unverified — safety number not compared"
- "? Sent anonymously"
- "Note deleted after reading (read-once)."

Use this plan as the single source. Implement slice by slice, verifying against flows, states, and zero-knowledge invariants at every step.

---

## I. Addendum — code-grounded corrections (read with §A–H; these override on conflict)

> Verified against `crates/crypto-wasm/src/lib.rs`, `crates/server/src/lib.rs`,
> `extension/background.js`/`popup.js`, `app/src/App.tsx`/`screens/Vault.tsx`,
> `extension/tokens.css`. Six items above need correction or are missing; they are
> correctness/security, not polish.

**I.1 — Filter reserved items out of the visible vault list (MISSING; a real bug).**
Both surfaces currently render *every* decrypted item: `background.js` `toMeta`/`LIST`
(builds `items` Map for all ids) and `app/src/App.tsx` `loadItems` (lines 15–25). The
reserved Send items (`bastion:send-identity`, `bastion:send-contacts`, and any
`bastion:send-prefs`) would otherwise appear as junk rows in the vault. **Add an
`id.startsWith("bastion:send-")` exclusion** wherever the vault list is built/sorted, on
both surfaces. Do this first in P3a.

**I.2 — Pin the full PublicIdentity, not `key_version` (SECURITY — corrects §A.5/§E/§H).**
§A line 126, §E line 392, and the `Contact.keyVersion` field (§H line 495) detect key change
by comparing `key_version`. Design §6 explicitly warns this is insufficient: a malicious
directory can swap `sig_pub` (forging sender auth) **without** bumping `key_version`, and the
safety number would no longer match. **Pin `pinFp = sha256(canonical PublicIdentity JSON)`**
at verify time and compare the whole public on every resolve/open. Keep `key_version` only as
a display hint, never as the trust tripwire.

**I.3 — Two-pass open for the verified upgrade + key-change-on-open (corrects §A.4/§D Open).**
§D's Open passes `contact ? contact.public : null` as `verify_sender_json`, but you don't know
the claimed `sender.id` until *after* you decrypt (the sender lives inside the ciphertext). Do:
```
r1 = send_open(blob, pass, undefined)              // discover sender.state/id
if r1.sender.state === "unverified" && verifiedContact(r1.sender.id):
   try r2 = send_open(blob, pass, JSON.stringify(contact.public)) // → "verified"
   catch: KEY_CHANGED(contact)  // sig failed vs pinned key → red banner, demote
```
Only the *verified-contact upgrade* re-opens; anonymous/unverified render from `r1`. (Passphrase
notes pay Argon2 twice only on that upgrade — rare, acceptable.)

**I.4 — Seal verified contacts to the PINNED key (SECURITY — corrects §A.3/§D Compose).**
§D Compose takes `recipPub` "from contacts or directory" without distinction. For a **verified**
contact, seal to the **pinned** `contact.public`, not a fresh `GET /send/directory` result —
otherwise a compromised directory swaps the key at send time and silently downgrades trust. Fetch
the directory only to *detect* change (compare to `pinFp`); on mismatch, stop and force re-verify.
TOFU/unverified still seals to the directory result (labeled unverified).

**I.5 — Send message verbs must stay extension-page-only (SECURITY — missing in §C).**
`background.js` gates content-script access via `CONTENT_ALLOWED` (line 35) and rejects privileged
verbs from non-extension senders (the `isExtPage` check, lines 349–353). The new
`SEND_*`/`CONTACTS_*` verbs must **not** be added to `CONTENT_ALLOWED` — Send is popup-only, so a
content script on an arbitrary web page can never reach a user's inbox, identity, or contacts.
State this in the message-router section.

**I.6 — Multi-device: guard `create_send_identity` behind `whoami` (corrects §A.1/§G).**
`create_send_identity()` "Replaces any existing one" (lib.rs:202) and bumps a fresh keyring. If
device B runs enable while device A already published, B mints a second identity → A's in-flight
notes orphan. Before `create_*`, call `GET /send/whoami`: if it returns a `bastion_id` but the
local vault lacks `send_identity_item_id()`, **do not create** — surface "Send is already enabled
on this account; unlock the device that has it, or rotate." Only `create` when whoami is `404`.

**I.7 — Caps to surface in UI (from `crates/server/src/lib.rs`):** blob `MAX_SEND_BLOB`
**256 KiB** (compose counter target), inbox quota `MAX_INBOX` **500**, inbox page cap **100**
(paginate by deleting), rate limits — sender **60/min**, sender-recipient pair **30/min**,
recipient aggregate **120/min**, lookup **120/min**.
The `429` copy should disambiguate "you're sending too fast" vs "their inbox is full" (server text
is `"recipient inbox full"`).

---

*End of plan. Opinionated defaults chosen for calm, trustworthy, minimal-dependency UX that reuses every existing pattern.*
