import { describe, expect, it, vi } from "vitest";
import { deleteInboxMessage } from "./destructive-actions";

describe("deleteInboxMessage", () => {
  it("does not publish local deletion before the server confirms it", async () => {
    let confirmRemote: (() => void) | undefined;
    const deleteRemote = vi.fn(
      () => new Promise<void>((resolve) => {
        confirmRemote = resolve;
      })
    );
    const commitLocal = vi.fn();
    const toast = vi.fn();

    const result = deleteInboxMessage(deleteRemote, commitLocal, toast);
    expect(commitLocal).not.toHaveBeenCalled();
    expect(toast).not.toHaveBeenCalled();

    confirmRemote?.();
    await expect(result).resolves.toBe(true);
    expect(commitLocal).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith("Message deleted");
  });

  it("retains local state and reports failure when the server rejects deletion", async () => {
    const commitLocal = vi.fn();
    const toast = vi.fn();

    await expect(
      deleteInboxMessage(
        vi.fn(async () => {
          throw new Error("network failure");
        }),
        commitLocal,
        toast
      )
    ).resolves.toBe(false);

    expect(commitLocal).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledOnce();
    expect(toast).toHaveBeenCalledWith("Message was not deleted");
  });
});
