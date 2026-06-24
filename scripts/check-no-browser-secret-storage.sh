#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Guard: the web app must NEVER persist secrets in browser-side storage.
#
# Why: localStorage / sessionStorage / IndexedDB / cookies are readable by ANY
# same-origin script. An infostealer (or an XSS payload) reads them directly
# from disk or the DOM — no need to win the race against an in-memory key.
# Our model keeps unlocked secrets in WASM memory only, for as short a time as
# possible (see crypto-wasm Account::lock / reveal_secret). Persisting anything
# secret to these APIs would defeat that. This guard fails the build if such an
# API appears in the web app code.
#
# Scope: web/ (static demo), app/src/ (the Bastion React app) and extension/
# (the Chrome extension — which keeps the unlocked session in chrome.storage.
# session, RAM-only, NOT in the forbidden disk-backed APIs below) — EXCLUDING
# the generated pkg/ wasm-bindgen glue (a build artifact we do not control).
#
# Escape hatch: if a NON-secret value ever legitimately needs persistence, add
# the marker `storage-guard:allow` in a comment on the same line. Use sparingly
# and never for anything derived from the vault key, the Secret Key, the master
# password, or decrypted item contents.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

# Forbidden browser persistence APIs.
PATTERN='localStorage|sessionStorage|indexedDB|document\.cookie'

# Search web/ app CODE (html/js/ts variants), excluding the generated pkg/ glue.
# Docs (*.md) are out of scope: they may name these APIs to describe the rule.
# grep exit code: 0 = match found (a violation), 1 = no match (clean).
hits="$(grep -rnE "$PATTERN" web/ app/src/ extension/ \
  --exclude-dir=pkg \
  --exclude-dir=node_modules --exclude-dir=dist \
  --include='*.html' --include='*.htm' \
  --include='*.js' --include='*.mjs' --include='*.cjs' \
  --include='*.ts' --include='*.tsx' --include='*.jsx' \
  | grep -v 'storage-guard:allow' || true)"

if [ -n "$hits" ]; then
  echo "❌ Browser secret-storage guard FAILED."
  echo "   Persisting to browser storage is forbidden (infostealer surface)."
  echo "   Offending lines:"
  echo "$hits" | sed 's/^/     /'
  echo
  echo "   If this is a non-secret value that genuinely needs persistence,"
  echo "   annotate the line with a 'storage-guard:allow' comment."
  exit 1
fi

echo "✅ Browser secret-storage guard passed: no localStorage/sessionStorage/IndexedDB/cookie use in web/, app/ or extension/ code."
