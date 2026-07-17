import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Welcome } from "./Welcome";

function renderWelcome() {
  const onCreate = vi.fn(async () => {});
  render(<Welcome onCreate={onCreate} onHaveVault={vi.fn()} />);
  return { onCreate };
}

async function fill(user: ReturnType<typeof userEvent.setup>, email: string, pw: string) {
  await user.type(screen.getByPlaceholderText("you@example.com"), email);
  await user.type(screen.getByPlaceholderText("A long, memorable passphrase"), pw);
  await user.type(screen.getByPlaceholderText("Repeat it"), pw);
}

describe("Welcome master-password strength gate", () => {
  it("refuses a weak master password and does not create the vault", async () => {
    const user = userEvent.setup();
    const { onCreate } = renderWelcome();

    await fill(user, "alice@example.com", "password"); // common word, 8 chars
    await user.click(screen.getByRole("button", { name: "Create vault" }));

    expect(screen.getByText(/too weak/i)).toBeInTheDocument();
    expect(onCreate).not.toHaveBeenCalled();
  });

  it("accepts a strong passphrase and proceeds to create the vault", async () => {
    const user = userEvent.setup();
    const { onCreate } = renderWelcome();

    await fill(user, "alice@example.com", "maple-tiger-river-cloud-echo");
    await user.click(screen.getByRole("button", { name: "Create vault" }));

    // create() paints "Creating…" via a short timeout before calling onCreate.
    await waitFor(() =>
      expect(onCreate).toHaveBeenCalledWith("alice@example.com", "maple-tiger-river-cloud-echo")
    );
  });
});
