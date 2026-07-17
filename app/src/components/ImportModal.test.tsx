import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import {
  MAX_CSV_BYTES,
  type ImportOutcome,
  type ImportProgress,
  type ImportResult,
} from "../lib/import";
import type { VaultItem } from "../lib/types";
import { ImportModal } from "./ImportModal";

describe("ImportModal", () => {
  it("stays open, reports progress, and closes only after a confirmed result", async () => {
    const user = userEvent.setup();
    let reportProgress: ImportProgress | undefined;
    let finishImport: ((outcome: ImportOutcome) => void) | undefined;
    const onImport = vi.fn(
      (_result: ImportResult, onProgress: ImportProgress) =>
        new Promise<ImportOutcome>((resolve) => {
          reportProgress = onProgress;
          finishImport = resolve;
        })
    );
    const onClose = vi.fn();
    render(<ImportModal existingItems={[]} onImport={onImport} onClose={onClose} />);

    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    expect(fileInput).not.toBeNull();
    await user.upload(
      fileInput!,
      new File(["name,username,password\nGitHub,general,secret"], "vault.csv", {
        type: "text/csv",
      })
    );

    const importButton = await screen.findByRole("button", { name: "Import 1 items" });
    await user.click(importButton);
    expect(onImport).toHaveBeenCalledOnce();
    expect(screen.getByRole("button", { name: "Importing 0/1…" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Close dialog" })).toBeDisabled();
    expect(onClose).not.toHaveBeenCalled();

    act(() => reportProgress?.(1, 1));
    expect(screen.getByRole("progressbar", { name: "CSV import progress" })).toHaveValue(1);

    act(() => finishImport?.({ requested: 1, imported: 1 }));
    await waitFor(() =>
      expect(screen.getByText("Imported 1 of 1 items.")).toBeVisible()
    );
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledOnce();
  });

  it("rejects oversized files before reading or parsing them", async () => {
    const user = userEvent.setup();
    const onImport = vi.fn(async () => ({ requested: 0, imported: 0 }));
    render(<ImportModal existingItems={[]} onImport={onImport} onClose={vi.fn()} />);

    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]');
    await user.upload(
      fileInput!,
      new File([new Uint8Array(MAX_CSV_BYTES + 1)], "oversized.csv", { type: "text/csv" })
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("CSV files cannot exceed 5 MiB.");
    expect(onImport).not.toHaveBeenCalled();
  });

  it("skips exact duplicates unless the user explicitly includes them", async () => {
    const user = userEvent.setup();
    const existing: VaultItem = {
      id: "existing",
      type: "login",
      title: "GitHub",
      username: "general",
      password: "secret",
      updatedAt: 1,
    };
    const onImport = vi.fn(async (result: ImportResult) => ({
      requested: result.items.length,
      imported: result.items.length,
    }));
    render(<ImportModal existingItems={[existing]} onImport={onImport} onClose={vi.fn()} />);

    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"]')!;
    await user.upload(
      fileInput,
      new File(["name,username,password\nGitHub,general,secret"], "vault.csv", { type: "text/csv" })
    );

    expect(await screen.findByText("1 exact duplicate(s) skipped by default.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Import 0 items" })).toBeDisabled();

    await user.click(screen.getByRole("checkbox", { name: "Import exact duplicates anyway" }));
    await user.click(screen.getByRole("button", { name: "Import 1 items" }));
    expect(onImport.mock.calls[0][0].items).toHaveLength(1);
  });
});
