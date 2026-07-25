import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { VaultItem } from "../lib/types";
import { Vault } from "./Vault";

const LOGIN: VaultItem = {
  id: "login-1",
  type: "login",
  title: "GitHub",
  username: "general@example.com",
  password: "abc",
  url: "https://github.com",
  updatedAt: 1_700_000_000_000,
};

const CARD: VaultItem = {
  id: "card-1",
  type: "card",
  title: "Operations card",
  cardNumber: "4111111111111111",
  cardExp: "12/29",
  cardCvv: "123",
  updatedAt: 1_700_000_000_000,
};

function renderVault(items: VaultItem[] = [LOGIN], syncStatus: "saved" | "saving" | "error" = "saved") {
  const onUpsert = vi.fn(async () => true);
  const onTrash = vi.fn(async () => true);
  const onDelete = vi.fn(async () => true);
  const onDeleteMany = vi.fn(async () => true);
  render(
    <Vault
      email="general@example.com"
      items={items}
      account={null}
      token={null}
      sendContacts={[]}
      setSendContacts={vi.fn()}
      persistEncryptedItem={vi.fn(async () => {})}
      onUpsert={onUpsert}
      onTrash={onTrash}
      onDelete={onDelete}
      onDeleteMany={onDeleteMany}
      onImport={vi.fn(async (result) => ({
        requested: result.items.length,
        imported: result.items.length,
      }))}
      syncStatus={syncStatus}
      onLock={vi.fn()}
      toast={vi.fn()}
    />
  );
  return { onDelete, onDeleteMany, onTrash, onUpsert };
}

describe("Vault dashboard accessibility", () => {
  it("enables implemented destinations and leaves email masking unavailable", () => {
    renderVault();
    expect(screen.getByRole("button", { name: "Trash 0" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Personal" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Email Masking Requires relay" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Breach Scanner" })).toBeEnabled();
  });

  it("reveals card secrets independently and conceals them after the deadline", async () => {
    vi.useFakeTimers();
    try {
      renderVault([CARD]);
      fireEvent.click(screen.getByRole("button", { name: "Open Operations card" }));

      fireEvent.click(screen.getByRole("button", { name: "Reveal number" }));
      expect(screen.getByText(CARD.cardNumber!)).toBeVisible();
      expect(screen.queryByText(CARD.cardCvv!)).not.toBeInTheDocument();

      fireEvent.click(screen.getByRole("button", { name: "Reveal cvv" }));
      expect(screen.getByText(CARD.cardCvv!)).toBeVisible();

      await act(() => vi.advanceTimersByTimeAsync(30_000));
      expect(screen.queryByText(CARD.cardNumber!)).not.toBeInTheDocument();
      expect(screen.queryByText(CARD.cardCvv!)).not.toBeInTheDocument();
    } finally {
      vi.useRealTimers();
    }
  });

  it.each([
    ["window blur", () => fireEvent.blur(window)],
    ["page hide", () => fireEvent.pageHide(window)],
  ])("conceals every revealed secret on %s", (_name, leaveWindow) => {
    renderVault([CARD]);
    fireEvent.click(screen.getByRole("button", { name: "Open Operations card" }));
    fireEvent.click(screen.getByRole("button", { name: "Reveal number" }));
    fireEvent.click(screen.getByRole("button", { name: "Reveal cvv" }));
    expect(screen.getByText(CARD.cardNumber!)).toBeVisible();
    expect(screen.getByText(CARD.cardCvv!)).toBeVisible();

    act(leaveWindow);

    expect(screen.queryByText(CARD.cardNumber!)).not.toBeInTheDocument();
    expect(screen.queryByText(CARD.cardCvv!)).not.toBeInTheDocument();
    // The detail view stays open — concealing is not locking.
    expect(screen.getByRole("button", { name: "Reveal number" })).toHaveAttribute(
      "aria-pressed",
      "false"
    );
  });

  it("warns in the item detail when the saved website is cleartext HTTP", () => {
    renderVault([{ ...LOGIN, id: "http-1", title: "Router", url: "http://192.168.1.1/admin" }]);
    fireEvent.click(screen.getByRole("button", { name: "Open Router" }));

    expect(screen.getByText("Not secure · HTTP")).toBeVisible();
    // The link still works and the value stays copyable — this is a warning.
    expect(screen.getByRole("link", { name: "Open website in a new tab" })).toHaveAttribute(
      "href",
      "http://192.168.1.1/admin"
    );
  });

  it("does not warn for an HTTPS website", () => {
    renderVault([LOGIN]);
    fireEvent.click(screen.getByRole("button", { name: "Open GitHub" }));

    expect(screen.queryByText("Not secure · HTTP")).not.toBeInTheDocument();
  });

  it("announces only transaction-backed sync states", () => {
    renderVault([], "saving");
    expect(screen.getByRole("status")).toHaveTextContent("Saving…");
  });

  it("publishes current navigation, filter, and generator control states", async () => {
    const user = userEvent.setup();
    renderVault();

    const vaultNav = screen.getByRole("button", { name: "Vault" });
    expect(vaultNav).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: /All Items/ })).toHaveAttribute(
      "aria-pressed",
      "true"
    );

    const generatorNav = screen.getByRole("button", { name: "Password Generator" });
    await user.click(generatorNav);
    expect(vaultNav).not.toHaveAttribute("aria-current");
    expect(generatorNav).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("button", { name: "Regenerate password" })).toBeVisible();
    expect(screen.getByRole("slider", { name: "Password length" })).toHaveValue("20");
    expect(screen.getByRole("button", { name: "Include uppercase letters" })).toHaveAttribute(
      "aria-pressed",
      "true"
    );
  });

  it("filters favorites independently and exposes the pressed state", async () => {
    const user = userEvent.setup();
    renderVault([
      { ...LOGIN, favorite: true },
      { id: "note-1", type: "note", title: "Recovery", updatedAt: LOGIN.updatedAt + 1 },
    ]);

    const favorites = screen.getByRole("button", { name: /Favorites/ });
    await user.click(favorites);
    expect(favorites).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Open GitHub" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open Recovery" })).not.toBeInTheDocument();
  });

  it("updates semantic relative timestamps on a minute boundary", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(LOGIN.updatedAt + 30_000);
    try {
      renderVault();
      const timestamp = screen.getByText("just now");
      expect(timestamp.tagName).toBe("TIME");
      expect(timestamp).toHaveAttribute("datetime", new Date(LOGIN.updatedAt).toISOString());

      await act(() => vi.advanceTimersByTimeAsync(60_000));
      expect(screen.getByText("1m ago")).toBeVisible();
    } finally {
      vi.useRealTimers();
    }
  });

  it("changes vault ordering through the explicit sort control", async () => {
    const user = userEvent.setup();
    renderVault([
      { ...LOGIN, id: "z", title: "Zulu" },
      { ...LOGIN, id: "a", title: "Alpha" },
    ]);
    await user.selectOptions(screen.getByRole("combobox", { name: "Sort vault items" }), "name");
    const rows = screen.getAllByRole("button", { name: /^Open (Alpha|Zulu)$/ });
    expect(rows.map((row) => row.getAttribute("aria-label"))).toEqual(["Open Alpha", "Open Zulu"]);
  });

  it("opens a vault row from the keyboard and restores focus after dismissal", async () => {
    const user = userEvent.setup();
    renderVault();

    const openItem = screen.getByRole("button", { name: "Open GitHub" });
    expect(screen.getByRole("button", { name: "Copy password for GitHub" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Edit GitHub" })).toBeVisible();

    openItem.focus();
    await user.keyboard("{Enter}");
    expect(screen.getByRole("dialog", { name: "GitHub" })).toBeVisible();

    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(openItem).toHaveFocus();
  });

  it("offers an isolated open action only for a safe website URL", async () => {
    const user = userEvent.setup();
    renderVault();
    await user.click(screen.getByRole("button", { name: "Open GitHub" }));

    const open = screen.getByRole("link", { name: "Open website in a new tab" });
    expect(open).toHaveAttribute("href", "https://github.com/");
    expect(open).toHaveAttribute("target", "_blank");
    expect(open).toHaveAttribute("rel", "noopener noreferrer");
    expect(open).toHaveAttribute("referrerpolicy", "no-referrer");
  });

  it("requires explicit confirmation before moving a vault item to trash", async () => {
    const user = userEvent.setup();
    const { onTrash } = renderVault();

    await user.click(screen.getByRole("button", { name: "Open GitHub" }));
    await user.click(screen.getByRole("button", { name: "Move to trash" }));

    expect(screen.getByRole("dialog", { name: "Move GitHub to trash?" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(onTrash).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Move to trash" }));
    expect(onTrash).toHaveBeenCalledOnce();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("restores a trashed item without exposing it in the active vault", async () => {
    const user = userEvent.setup();
    const deleted = { ...LOGIN, deletedAt: LOGIN.updatedAt + 1 };
    const { onUpsert } = renderVault([deleted]);

    expect(screen.queryByRole("button", { name: "Open GitHub" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Trash 1" }));
    await user.click(screen.getByRole("button", { name: "Restore" }));

    expect(onUpsert).toHaveBeenCalledWith(expect.objectContaining({ id: LOGIN.id, deletedAt: undefined }));
  });

  it("filters items through encrypted folder metadata", async () => {
    const user = userEvent.setup();
    renderVault([
      { ...LOGIN, folder: "Personal" },
      { ...LOGIN, id: "work", title: "Work account", folder: "Work" },
    ]);

    await user.click(screen.getByRole("button", { name: "Work" }));
    expect(screen.getByRole("button", { name: "Open Work account" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open GitHub" })).not.toBeInTheDocument();
  });

  it("treats existing unfiled items as Personal", async () => {
    const user = userEvent.setup();
    renderVault([LOGIN, { ...LOGIN, id: "work", title: "Work account", folder: "Work" }]);

    await user.click(screen.getByRole("button", { name: "Personal" }));
    expect(screen.getByRole("button", { name: "Open GitHub" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Open Work account" })).not.toBeInTheDocument();
  });

  it("requires explicit consent before a breach scan can start", async () => {
    const user = userEvent.setup();
    renderVault();

    await user.click(screen.getByRole("button", { name: "Breach Scanner" }));
    const scan = screen.getByRole("button", { name: "Scan passwords" });
    expect(scan).toBeDisabled();
    await user.click(screen.getByRole("checkbox"));
    expect(scan).toBeEnabled();
  });

  it("controls the mobile navigation drawer and contains its keyboard focus", async () => {
    const user = userEvent.setup();
    renderVault();

    const toggle = screen.getByRole("button", { name: "Open navigation" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");

    await user.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByRole("button", { name: "Dismiss navigation" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Vault" })).toHaveFocus();
    expect(document.body).toHaveStyle({ overflow: "hidden" });

    await user.tab({ shift: true });
    expect(screen.getByRole("button", { name: "Lock vault" })).toHaveFocus();
    await user.keyboard("{Escape}");

    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveFocus();
    expect(document.body).not.toHaveStyle({ overflow: "hidden" });
  });

  it("focuses metadata-only search with accurate keyboard shortcuts", async () => {
    const user = userEvent.setup();
    renderVault();

    await user.click(screen.getByRole("button", { name: "Password Generator" }));
    await user.keyboard("{Control>}k{/Control}");

    const search = screen.getByRole("textbox", { name: "Search vault items" });
    expect(search).toHaveFocus();
    expect(screen.getByRole("heading", { name: "Vault" })).toBeVisible();
    expect(screen.getByText("Ctrl/⌘ K")).toBeVisible();

    await user.type(search, "github");
    expect(screen.getByText("1 result for “github”")).toHaveAttribute("role", "status");
    await user.keyboard("{Escape}");
    expect(search).toHaveValue("");

    await user.type(search, "abc");
    expect(screen.getByText("No matching items")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Clear search" }));
    expect(screen.getByRole("button", { name: "Open GitHub" })).toBeVisible();

    search.blur();
    await user.keyboard("/");
    expect(search).toHaveFocus();
  });

  it("opens health findings through native keyboard button behavior", async () => {
    const user = userEvent.setup();
    renderVault();

    await user.click(screen.getByRole("button", { name: "Password Health" }));
    // The fixture's password is both weak and old, so it is listed in two
    // findings sections; keyboard behavior is identical — use the first.
    const finding = screen.getAllByRole("button", { name: /GitHub/ })[0];
    finding.focus();
    await user.keyboard(" ");

    expect(screen.getByRole("dialog", { name: "GitHub" })).toBeVisible();
  });

  it("does not present an empty vault as a perfect health score", async () => {
    const user = userEvent.setup();
    renderVault([]);

    await user.click(screen.getByRole("button", { name: "Password Health" }));
    expect(screen.getByText("not scored")).toBeVisible();
    expect(screen.queryByRole("progressbar", { name: "Vault health score" })).not.toBeInTheDocument();
    expect(screen.getByText("Add a login with a password to calculate vault health.")).toBeVisible();
  });
});
