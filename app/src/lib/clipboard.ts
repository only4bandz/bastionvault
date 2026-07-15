export type ClipboardWriter = Pick<Clipboard, "writeText">;

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
    toast(`${label} copied`);
    return true;
  } catch {
    toast(`${label} was not copied`);
    return false;
  }
}
