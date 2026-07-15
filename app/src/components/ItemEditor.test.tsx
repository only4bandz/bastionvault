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
  cardNumber: "4111111111111111",
  cardExp: "12/29",
  cardCvv: "123",
  updatedAt: 1,
};

describe("ItemEditor secret fields", () => {
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
