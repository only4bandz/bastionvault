import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { VaultItem } from "../lib/types";
import { ItemEditor } from "./ItemEditor";

const LOGIN: VaultItem = {
  id: "login",
  type: "login",
  title: "GitHub",
  username: "general@example.com",
  password: "login-secret",
  url: "https://github.com",
  updatedAt: 1,
};

const CARD: VaultItem = {
  id: "card",
  type: "card",
  title: "Operations card",
  cardholderName: "General Example",
  cardNumber: "4111111111111111",
  cardExp: "12/29",
  cardCvv: "123",
  updatedAt: 1,
};

describe("ItemEditor secret fields", () => {
  it("requires confirmation before discarding a user-edited draft", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<ItemEditor initial={LOGIN} onSave={vi.fn(async () => true)} onClose={onClose} />);

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "GitLab");
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(screen.getByRole("dialog", { name: "Discard unsaved changes?" })).toBeVisible();
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.getByLabelText("Name")).toHaveValue("GitLab");

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Discard changes" }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("closes an untouched editor without prompting", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(<ItemEditor initial={LOGIN} onSave={vi.fn(async () => true)} onClose={onClose} />);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(onClose).toHaveBeenCalledOnce();
    expect(screen.queryByRole("dialog", { name: "Discard unsaved changes?" })).not.toBeInTheDocument();
  });

  it("masks a saved login password and submits the unchanged secret", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn(async (_item: VaultItem) => false);
    render(<ItemEditor initial={LOGIN} onSave={onSave} onClose={vi.fn()} />);

    const password = screen.getByLabelText("Password");
    expect(password).toHaveAttribute("type", "password");
    expect(password).toHaveAttribute("autocomplete", "new-password");
    expect(password).toHaveAttribute("spellcheck", "false");

    await user.click(screen.getByRole("button", { name: "Show password" }));
    expect(password).toHaveAttribute("type", "text");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect(onSave).toHaveBeenCalledOnce();
    expect(onSave.mock.calls[0][0]).toMatchObject({
      id: "login",
      password: "login-secret",
    });
  });

  it("masks card number and CVV independently with payment-field annotations", async () => {
    const user = userEvent.setup();
    render(<ItemEditor initial={CARD} onSave={vi.fn(async () => false)} onClose={vi.fn()} />);

    const cardNumber = screen.getByLabelText("Card number");
    const cvv = screen.getByLabelText("CVV");
    expect(screen.getByLabelText("Cardholder name")).toHaveValue("General Example");
    expect(screen.getByLabelText("Cardholder name")).toHaveAttribute("autocomplete", "cc-name");
    expect(cardNumber).toHaveAttribute("type", "password");
    expect(cardNumber).toHaveAttribute("autocomplete", "cc-number");
    expect(cardNumber).toHaveAttribute("inputmode", "numeric");
    expect(cvv).toHaveAttribute("type", "password");
    expect(cvv).toHaveAttribute("autocomplete", "cc-csc");
    expect(screen.getByLabelText("Expiry")).toHaveAttribute("autocomplete", "cc-exp");

    await user.click(screen.getByRole("button", { name: "Show card number" }));
    expect(cardNumber).toHaveAttribute("type", "text");
    expect(cvv).toHaveAttribute("type", "password");
  });
});

describe("password age tracking", () => {
  const IMPORTED: VaultItem = { ...LOGIN, updatedAt: 1_600_000_000_000 };

  it("pins the age of an imported password when an unrelated field is edited", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn(async (_item: VaultItem) => true);
    render(<ItemEditor initial={IMPORTED} onSave={onSave} onClose={vi.fn()} />);

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "GitLab");
    await user.click(screen.getByRole("button", { name: "Save" }));

    const saved = onSave.mock.calls[0][0];
    expect(saved.title).toBe("GitLab");
    // updatedAt moves; the password age does not follow it.
    expect(saved.updatedAt).toBeGreaterThan(IMPORTED.updatedAt);
    expect(saved.passwordChangedAt).toBe(IMPORTED.updatedAt);
  });

  it("resets the age when the password itself changes", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn(async (_item: VaultItem) => true);
    const before = Date.now();
    render(<ItemEditor initial={IMPORTED} onSave={onSave} onClose={vi.fn()} />);

    await user.clear(screen.getByLabelText("Password"));
    await user.type(screen.getByLabelText("Password"), "V7!kQ2#pL9@xR4$m");
    await user.click(screen.getByRole("button", { name: "Save" }));

    const saved = onSave.mock.calls[0][0];
    expect(saved.passwordChangedAt).toBeGreaterThanOrEqual(before);
  });

  it("keeps an explicit passwordChangedAt in preference to updatedAt", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn(async (_item: VaultItem) => true);
    const recorded = 1_500_000_000_000;
    render(
      <ItemEditor
        initial={{ ...IMPORTED, passwordChangedAt: recorded }}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "GitLab");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect((onSave.mock.calls[0][0]).passwordChangedAt).toBe(recorded);
  });

  it("records no password age for an item that has no password", async () => {
    const user = userEvent.setup();
    const onSave = vi.fn(async (_item: VaultItem) => true);
    render(
      <ItemEditor
        initial={{ id: "note", type: "note", title: "Wifi", notes: "ssid", updatedAt: 1 }}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    await user.clear(screen.getByLabelText("Name"));
    await user.type(screen.getByLabelText("Name"), "Wifi 5G");
    await user.click(screen.getByRole("button", { name: "Save" }));

    expect((onSave.mock.calls[0][0]).passwordChangedAt).toBeUndefined();
  });
});
