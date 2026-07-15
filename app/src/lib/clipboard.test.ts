import { describe, expect, it, vi } from "vitest";
import { copyWithFeedback, type ClipboardWriter } from "./clipboard";

describe("copyWithFeedback", () => {
  it("announces success only after the clipboard write resolves", async () => {
    let confirmWrite: (() => void) | undefined;
    const clipboard: ClipboardWriter = {
      writeText: vi.fn(
        () =>
          new Promise<void>((resolve) => {
            confirmWrite = resolve;
          })
      ),
    };
    const toast = vi.fn();

    const result = copyWithFeedback("secret", "Password", toast, clipboard);
    expect(clipboard.writeText).toHaveBeenCalledWith("secret");
    expect(toast).not.toHaveBeenCalled();

    confirmWrite?.();
    await expect(result).resolves.toBe(true);
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith("Password copied");
  });

  it("reports a rejected write without claiming success", async () => {
    const clipboard: ClipboardWriter = {
      writeText: vi.fn(async () => {
        throw new DOMException("Denied", "NotAllowedError");
      }),
    };
    const toast = vi.fn();

    await expect(copyWithFeedback("secret", "Secret Key", toast, clipboard)).resolves.toBe(
      false
    );
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith("Secret Key was not copied");
  });

  it("reports an unavailable Clipboard API", async () => {
    const toast = vi.fn();

    await expect(copyWithFeedback("secret", "Bastion address", toast, null)).resolves.toBe(
      false
    );
    expect(toast).toHaveBeenCalledWith("Bastion address was not copied");
  });
});
