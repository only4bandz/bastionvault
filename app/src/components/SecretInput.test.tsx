import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { SecretInput } from "./SecretInput";

describe("SecretInput", () => {
  it("masks by default and preserves the value across explicit reveal changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(
      <SecretInput
        id="password"
        label="Password"
        value="correct horse battery staple"
        onChange={onChange}
        autoComplete="new-password"
      />
    );

    const input = screen.getByDisplayValue("correct horse battery staple");
    const reveal = screen.getByRole("button", { name: "Show password" });
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "new-password");
    expect(reveal).toHaveAttribute("aria-pressed", "false");

    await user.click(reveal);
    expect(input).toHaveAttribute("type", "text");
    expect(input).toHaveValue("correct horse battery staple");
    expect(screen.getByRole("button", { name: "Hide password" })).toHaveAttribute(
      "aria-pressed",
      "true"
    );
    expect(onChange).not.toHaveBeenCalled();
  });

  it("keeps reveal state isolated between secret fields", async () => {
    const user = userEvent.setup();
    render(
      <>
        <SecretInput label="Card number" value="4111111111111111" readOnly />
        <SecretInput label="CVV" value="123" readOnly />
      </>
    );

    await user.click(screen.getByRole("button", { name: "Show card number" }));
    expect(screen.getByDisplayValue("4111111111111111")).toHaveAttribute("type", "text");
    expect(screen.getByDisplayValue("123")).toHaveAttribute("type", "password");
  });
});
