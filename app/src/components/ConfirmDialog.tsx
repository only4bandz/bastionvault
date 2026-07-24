import { useRef, useState, type JSX, type ReactNode } from "react";
import { Dialog } from "./Dialog";

export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  pendingLabel = "Working…",
  onClose,
  onConfirm,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  pendingLabel?: string;
  onClose: () => void;
  onConfirm: () => Promise<boolean>;
}): JSX.Element {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const [busy, setBusy] = useState(false);

  async function confirm(): Promise<void> {
    if (busy) return;
    setBusy(true);
    try {
      if (await onConfirm()) onClose();
      else setBusy(false);
    } catch {
      // onConfirm owns user-facing failure reporting. Keep the dialog open so
      // the user can retry or cancel even if a caller unexpectedly rejects.
      setBusy(false);
    }
  }

  return (
    <Dialog
      title={title}
      onClose={onClose}
      closeDisabled={busy}
      initialFocusRef={cancelRef}
      footer={
        <>
          <span className="spacer" />
          <button ref={cancelRef} className="btn btn-ghost" disabled={busy} onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-danger confirm-danger" disabled={busy} onClick={() => void confirm()}>
            {busy ? <><span className="spinner" aria-hidden="true" /> {pendingLabel}</> : confirmLabel}
          </button>
        </>
      }
    >
      <p className="confirm-copy">{children}</p>
    </Dialog>
  );
}
