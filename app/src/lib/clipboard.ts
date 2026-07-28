export type ClipboardWriter = Pick<Clipboard, "writeText">;

/** How long a copied secret is allowed to linger on the OS clipboard. */
export const SECRET_CLEAR_MS = 30_000;

/**
 * The Secret Key gets a longer window than an item password: the user is
 * pasting it into offline storage (a printout note, another manager), which
 * takes longer than a login form. But it must still expire — it is the
 * highest-value credential in the system and previously stayed on the OS
 * clipboard forever.
 */
export const SECRET_KEY_CLEAR_MS = 120_000;

// One shared timer + sequence: a newer copy (secret or not, through these
// helpers) must never be clobbered by an older copy's pending clear.
let clearTimer: ReturnType<typeof setTimeout> | undefined;
let copySequence = 0;

function noteCopy(): number {
  copySequence += 1;
  if (clearTimer !== undefined) {
    clearTimeout(clearTimer);
    clearTimer = undefined;
  }
  return copySequence;
}

/**
 * Wipe the clipboard NOW if a secret copied through these helpers still has a
 * pending scheduled clear. Called when the vault locks: a secret must not
 * outlive the session that produced it. No-op when nothing secret is pending
 * (never destroys an unrelated copy).
 */
export async function clearPendingSecretCopy(
  clipboard: ClipboardWriter | null = navigator.clipboard ?? null
): Promise<void> {
  if (clearTimer === undefined) return;
  noteCopy(); // cancel the scheduled clear; we are doing it synchronously
  await clipboard?.writeText("").catch(() => {
    // Best-effort: the document may have lost focus.
  });
}

/**
 * Copy a secret (password, CVV, card number…) and schedule a clipboard wipe.
 *
 * The wipe writes an empty string after `clearAfterMs` unless something newer
 * was copied through these helpers in the meantime. The Clipboard API doesn't
 * let us read-and-compare without an extra permission prompt, so a copy made
 * in another application inside the window is overwritten too — the standard
 * password-manager trade-off: a stale secret is worse than a lost snippet.
 */
export async function copySecretWithFeedback(
  text: string,
  label: string,
  toast: (message: string) => void,
  clipboard: ClipboardWriter | null = navigator.clipboard ?? null,
  clearAfterMs: number = SECRET_CLEAR_MS
): Promise<boolean> {
  if (!clipboard) {
    toast(`${label} was not copied`);
    return false;
  }
  try {
    await clipboard.writeText(text);
  } catch {
    toast(`${label} was not copied`);
    return false;
  }
  const sequence = noteCopy();
  clearTimer = setTimeout(() => {
    if (sequence !== copySequence) return;
    clearTimer = undefined;
    clipboard.writeText("").catch(() => {
      // Clearing is best-effort: the document may have lost focus.
    });
  }, clearAfterMs);
  toast(`${label} copied — clears in ${Math.round(clearAfterMs / 1000)}s`);
  return true;
}

/**
 * Copy text and report only the result confirmed by the Clipboard API.
 * Callers must never announce success before writeText resolves.
 */
export async function copyWithFeedback(
  text: string,
  label: string,
  toast: (message: string) => void,
  clipboard: ClipboardWriter | null = navigator.clipboard ?? null
): Promise<boolean> {
  if (!clipboard) {
    toast(`${label} was not copied`);
    return false;
  }

  try {
    await clipboard.writeText(text);
    // A newer non-secret copy owns the clipboard now; cancel any pending wipe
    // so it doesn't destroy what the user just copied.
    noteCopy();
    toast(`${label} copied`);
    return true;
  } catch {
    toast(`${label} was not copied`);
    return false;
  }
}
