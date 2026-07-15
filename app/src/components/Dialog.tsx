import {
  useEffect,
  useId,
  useRef,
  type JSX,
  type KeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";
import { IcX } from "./icons";

const FOCUSABLE = [
  "button:not([disabled])",
  "a[href]",
  "input:not([disabled]):not([type='hidden'])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "[tabindex]:not([tabindex='-1'])",
].join(",");

export function Dialog({
  title,
  children,
  footer,
  headerLeading,
  headerMeta,
  onClose,
  closeDisabled = false,
  initialFocusRef,
}: {
  title: string;
  children: ReactNode;
  footer?: ReactNode;
  headerLeading?: ReactNode;
  headerMeta?: ReactNode;
  onClose: () => void;
  closeDisabled?: boolean;
  initialFocusRef?: RefObject<HTMLElement | null>;
}): JSX.Element {
  const titleId = useId();
  const dialogRef = useRef<HTMLDivElement>(null);
  const restoreFocusRef = useRef(
    document.activeElement instanceof HTMLElement ? document.activeElement : null
  );
  const originalBodyOverflowRef = useRef(document.body.style.overflow);
  const onCloseRef = useRef(onClose);
  const closeDisabledRef = useRef(closeDisabled);
  onCloseRef.current = onClose;
  closeDisabledRef.current = closeDisabled;

  useEffect(() => {
    const restoreFocus = restoreFocusRef.current;
    const originalBodyOverflow = originalBodyOverflowRef.current;
    document.body.style.overflow = "hidden";
    (initialFocusRef?.current ?? dialogRef.current)?.focus();
    return () => {
      document.body.style.overflow = originalBodyOverflow;
      restoreFocus?.focus();
    };
  }, [initialFocusRef]);

  function close(): void {
    if (!closeDisabledRef.current) onCloseRef.current();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLDivElement>): void {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }
    if (event.key !== "Tab") return;

    const dialog = dialogRef.current;
    if (!dialog) return;
    const focusable = [...dialog.querySelectorAll<HTMLElement>(FOCUSABLE)];
    if (focusable.length === 0) {
      event.preventDefault();
      dialog.focus();
      return;
    }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && (document.activeElement === first || document.activeElement === dialog)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div
      className="overlay"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <div
        ref={dialogRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={handleKeyDown}
      >
        <div className="modal-head">
          {headerLeading}
          <h3 id={titleId}>{title}</h3>
          {headerMeta}
          <button
            className="icon-btn x"
            type="button"
            aria-label="Close dialog"
            disabled={closeDisabled}
            onClick={close}
          >
            <IcX size={18} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}
