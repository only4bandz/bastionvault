import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";

describe("ConfirmDialog", () => {
  it("puts focus on the safe action and cancels with Escape", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        title="Delete item?"
        confirmLabel="Delete item"
        onClose={onClose}
        onConfirm={vi.fn(async () => true)}
      >
        This cannot be undone.
      </ConfirmDialog>
    );

    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("locks dismissal while pending and stays open after an unconfirmed operation", async () => {
    const user = userEvent.setup();
    let finish: ((confirmed: boolean) => void) | undefined;
    const onConfirm = vi.fn(
      () => new Promise<boolean>((resolve) => {
        finish = resolve;
      })
    );
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        title="Remove contact?"
        confirmLabel="Remove contact"
        pendingLabel="Removing…"
        onClose={onClose}
        onConfirm={onConfirm}
      >
        The contact remains on other devices until sync completes.
      </ConfirmDialog>
    );

    await user.click(screen.getByRole("button", { name: "Remove contact" }));
    expect(screen.getByRole("button", { name: "Removing…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close dialog" })).toBeDisabled();
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();

    finish?.(false);
    await waitFor(() => expect(screen.getByRole("button", { name: "Remove contact" })).toBeEnabled());
    expect(onClose).not.toHaveBeenCalled();
  });

  it("closes only after the destructive operation is confirmed", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <ConfirmDialog
        title="Delete message?"
        confirmLabel="Delete message"
        onClose={onClose}
        onConfirm={vi.fn(async () => true)}
      >
        This permanently removes the message.
      </ConfirmDialog>
    );

    await user.click(screen.getByRole("button", { name: "Delete message" }));
    expect(onClose).toHaveBeenCalledOnce();
  });
});
