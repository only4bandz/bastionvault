import { useRef, useState } from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Dialog } from "./Dialog";

describe("Dialog", () => {
  it("exposes dialog semantics, closes with Escape, and restores focus", async () => {
    const user = userEvent.setup();

    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open</button>
          {open && (
            <Dialog title="Edit item" onClose={() => setOpen(false)}>
              <button>Action</button>
            </Dialog>
          )}
        </>
      );
    }

    render(<Harness />);
    const trigger = screen.getByRole("button", { name: "Open" });
    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Edit item" });
    expect(dialog).toHaveFocus();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("honors initial focus and traps keyboard focus", async () => {
    const user = userEvent.setup();

    function Harness() {
      const initial = useRef<HTMLButtonElement>(null);
      return (
        <Dialog title="Import" onClose={() => {}} initialFocusRef={initial}>
          <button ref={initial}>First action</button>
          <button>Last action</button>
        </Dialog>
      );
    }

    render(<Harness />);
    const first = screen.getByRole("button", { name: "First action" });
    const last = screen.getByRole("button", { name: "Last action" });
    expect(first).toHaveFocus();

    last.focus();
    await user.tab();
    expect(screen.getByRole("button", { name: "Close dialog" })).toHaveFocus();

    await user.tab({ shift: true });
    expect(last).toHaveFocus();
  });

  it("cannot be dismissed while a protected operation is running", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <Dialog title="Saving" onClose={onClose} closeDisabled>
        <span>Working</span>
      </Dialog>
    );

    expect(screen.getByRole("button", { name: "Close dialog" })).toBeDisabled();
    await user.keyboard("{Escape}");
    await user.click(document.querySelector(".overlay") as HTMLElement);
    expect(onClose).not.toHaveBeenCalled();
  });
});
