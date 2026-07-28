import { act, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Generator } from "./Generator";

/** The generated value currently rendered in the output row. */
function shownValue(): string {
  const el = document.querySelector(".gen-out .val");
  return el?.textContent ?? "";
}

describe("Generator", () => {
  it("conceals the generated password when the window loses focus", async () => {
    render(<Generator toast={vi.fn()} />);
    const generated = shownValue();
    expect(generated).not.toBe("");
    expect(generated).not.toMatch(/^•+$/);

    act(() => {
      window.dispatchEvent(new Event("blur"));
    });
    // Masked, and the plaintext is no longer anywhere in the row.
    expect(shownValue()).toMatch(/^•+$/);
    expect(document.querySelector(".gen-out")?.textContent).not.toContain(generated);

    // One click brings it back — the same value, not a new one.
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /^Show generated/ }));
    expect(shownValue()).toBe(generated);
  });

  it("conceals when the tab is hidden", () => {
    render(<Generator toast={vi.fn()} />);
    expect(shownValue()).not.toMatch(/^•+$/);

    const visibility = vi.spyOn(document, "visibilityState", "get").mockReturnValue("hidden");
    act(() => {
      document.dispatchEvent(new Event("visibilitychange"));
    });
    expect(shownValue()).toMatch(/^•+$/);
    visibility.mockRestore();
  });

  it("shows a freshly regenerated password without an extra click", async () => {
    const user = userEvent.setup();
    render(<Generator toast={vi.fn()} />);

    act(() => {
      window.dispatchEvent(new Event("blur"));
    });
    expect(shownValue()).toMatch(/^•+$/);

    await user.click(screen.getByRole("button", { name: /^Regenerate/ }));
    const regenerated = shownValue();
    expect(regenerated).not.toMatch(/^•+$/);
    expect(regenerated).not.toBe("");
  });
});
