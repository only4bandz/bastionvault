import { render, screen } from "@testing-library/react";
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

function renderVault(items: VaultItem[] = [LOGIN]) {
  const onUpsert = vi.fn(async () => true);
  const onDelete = vi.fn(async () => true);
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
      onDelete={onDelete}
      onImport={vi.fn(async (result) => ({
        requested: result.items.length,
        imported: result.items.length,
      }))}
      onLock={vi.fn()}
      toast={vi.fn()}
    />
  );
  return { onDelete, onUpsert };
}

describe("Vault dashboard accessibility", () => {
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

  it("requires explicit confirmation before deleting a vault item", async () => {
    const user = userEvent.setup();
    const { onDelete } = renderVault();

    await user.click(screen.getByRole("button", { name: "Open GitHub" }));
    await user.click(screen.getByRole("button", { name: "Delete" }));

    expect(screen.getByRole("dialog", { name: "Delete GitHub?" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(onDelete).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Delete item" }));
    expect(onDelete).toHaveBeenCalledOnce();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
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
    expect(screen.getByRole("status")).toHaveTextContent("1 result for “github”");
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
