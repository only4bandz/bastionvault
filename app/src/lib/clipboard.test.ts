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

import { afterEach, beforeEach } from "vitest";
import { clearPendingSecretCopy, copySecretWithFeedback, SECRET_CLEAR_MS, SECRET_KEY_CLEAR_MS } from "./clipboard";

describe("copySecretWithFeedback", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function writer() {
    const writes: string[] = [];
    const clipboard: ClipboardWriter = {
      writeText: vi.fn(async (text: string) => {
        writes.push(text);
      }),
    };
    return { clipboard, writes };
  }

  it("wipes the clipboard after the clear delay", async () => {
    const { clipboard, writes } = writer();
    const toast = vi.fn();

    await expect(copySecretWithFeedback("hunter2", "Password", toast, clipboard)).resolves.toBe(
      true
    );
    expect(writes).toEqual(["hunter2"]);
    expect(toast).toHaveBeenCalledWith("Password copied — clears in 30s");

    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS - 1);
    expect(writes).toEqual(["hunter2"]);
    await vi.advanceTimersByTimeAsync(1);
    expect(writes).toEqual(["hunter2", ""]);
  });

  it("a newer secret copy cancels the older pending wipe", async () => {
    const { clipboard, writes } = writer();
    const toast = vi.fn();

    await copySecretWithFeedback("first", "Password", toast, clipboard);
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS / 2);
    await copySecretWithFeedback("second", "CVV", toast, clipboard);

    // The first copy's deadline passes: nothing is wiped yet.
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS / 2);
    expect(writes).toEqual(["first", "second"]);

    // The second copy's own deadline wipes exactly once.
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS / 2);
    expect(writes).toEqual(["first", "second", ""]);
  });

  it("a newer plain copy cancels the pending wipe", async () => {
    const { clipboard, writes } = writer();
    const toast = vi.fn();

    await copySecretWithFeedback("hunter2", "Password", toast, clipboard);
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS / 2);
    await copyWithFeedback("alice@example.com", "Username", toast, clipboard);

    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS * 2);
    expect(writes).toEqual(["hunter2", "alice@example.com"]);
  });

  it("clearPendingSecretCopy wipes immediately and cancels the timer", async () => {
    const { clipboard, writes } = writer();
    const toast = vi.fn();

    await copySecretWithFeedback("hunter2", "Password", toast, clipboard);
    await clearPendingSecretCopy(clipboard);
    expect(writes).toEqual(["hunter2", ""]);

    // The original 30s deadline passes: no double wipe.
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS * 2);
    expect(writes).toEqual(["hunter2", ""]);
  });

  it("clearPendingSecretCopy is a no-op without a pending secret", async () => {
    const { clipboard, writes } = writer();
    const toast = vi.fn();

    // Nothing copied at all.
    await clearPendingSecretCopy(clipboard);
    expect(writes).toEqual([]);

    // A non-secret copy owns the clipboard: locking must not destroy it.
    await copyWithFeedback("alice@example.com", "Username", toast, clipboard);
    await clearPendingSecretCopy(clipboard);
    expect(writes).toEqual(["alice@example.com"]);
  });

  it("does not schedule a wipe when the write fails", async () => {
    const clipboard: ClipboardWriter = {
      writeText: vi.fn(async () => {
        throw new DOMException("Denied", "NotAllowedError");
      }),
    };
    const toast = vi.fn();

    await expect(copySecretWithFeedback("secret", "Password", toast, clipboard)).resolves.toBe(
      false
    );
    expect(toast).toHaveBeenCalledWith("Password was not copied");
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS * 2);
    expect(clipboard.writeText).toHaveBeenCalledTimes(1);
  });
});

describe("SECRET_KEY_CLEAR_MS", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("honors the longer Secret Key window and still expires", async () => {
    const writes: string[] = [];
    const clipboard: ClipboardWriter = {
      writeText: vi.fn(async (text: string) => {
        writes.push(text);
      }),
    };
    const toast = vi.fn();

    await copySecretWithFeedback("A1-XXXXX", "Secret Key", toast, clipboard, SECRET_KEY_CLEAR_MS);
    expect(toast).toHaveBeenCalledWith("Secret Key copied — clears in 120s");

    // The default secret window passing must NOT wipe the longer copy…
    await vi.advanceTimersByTimeAsync(SECRET_CLEAR_MS);
    expect(writes).toEqual(["A1-XXXXX"]);
    // …but the Secret Key deadline must.
    await vi.advanceTimersByTimeAsync(SECRET_KEY_CLEAR_MS - SECRET_CLEAR_MS);
    expect(writes).toEqual(["A1-XXXXX", ""]);
  });
});
