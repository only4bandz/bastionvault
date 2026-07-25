import { useEffect, useMemo, useRef, useState, type JSX, type KeyboardEvent } from "react";
import { Brand } from "../components/Brand";
import { Generator } from "../components/Generator";
import { ItemEditor } from "../components/ItemEditor";
import { ImportModal } from "../components/ImportModal";
import { Dialog } from "../components/Dialog";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { Favicon } from "../components/Favicon";
import {
  IcBreach, IcCard, IcCopy, IcEdit, IcEye, IcFolder, IcGen, IcHealth, IcKey,
  IcDownload, IcExternal, IcLock, IcMask, IcMenu, IcNote, IcPlus, IcSearch, IcShared, IcStar, IcTrash, IcUpload, IcVault, IcX,
} from "../components/icons";
import { TYPE_LABEL, type ItemType, type VaultItem } from "../lib/types";
import { analyzePasswordHealth, passwordAgeReference } from "../lib/password-health";
import { downloadCsv, exportFilename, itemsToCsv } from "../lib/export";
import { lookupBin } from "../lib/bin";
import type { ImportOutcome, ImportProgress, ImportResult } from "../lib/import";
import type { Account } from "../lib/wasm";
import type { Contact } from "../lib/send";
import type { Blob } from "../lib/api";
import { filterVaultItems, type VaultSort } from "../lib/vault-search";
import { copySecretWithFeedback, copyWithFeedback } from "../lib/clipboard";
import { safeWebsiteUrl } from "../lib/safe-url";
import { relativeItemTime } from "../lib/item-time";
import { Send } from "./Send";
import { BreachScanner } from "./BreachScanner";

/** Card subtitle that shows "Debit Card" / "Credit Card" once the BIN resolves. */
function CardSubtitle({ item }: { item: VaultItem }): JSX.Element {
  const bin = (item.cardNumber || "").replace(/\D/g, "").slice(0, 8);
  const [type, setType] = useState<string | undefined>(item.cardType);
  useEffect(() => {
    if (item.cardType) {
      setType(item.cardType);
      return;
    }
    if (bin.length < 6) return;
    let active = true;
    lookupBin(bin).then((r) => active && r?.cardType && setType(r.cardType));
    return () => {
      active = false;
    };
  }, [bin, item.cardType]);
  const label = type ? `${type[0].toUpperCase()}${type.slice(1)} Card` : "Card";
  return <>{label}</>;
}

type Nav = "vault" | "trash" | "generator" | "health" | "breach" | "send";
export type VaultSyncStatus = "saved" | "saving" | "error";

const PAGE_SIZE = 50;
export const SECRET_REVEAL_MS = 30_000;
const DEFAULT_FOLDER = "Personal";

function itemFolder(item: VaultItem): string {
  return item.folder?.trim() || DEFAULT_FOLDER;
}

/** Page numbers to show, with "…" gaps for long ranges (e.g. 1 … 4 5 6 … 12). */
function pageNumbers(cur: number, total: number): (number | "…")[] {
  if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1);
  const out: (number | "…")[] = [1];
  const start = Math.max(2, cur - 1);
  const end = Math.min(total - 1, cur + 1);
  if (start > 2) out.push("…");
  for (let p = start; p <= end; p++) out.push(p);
  if (end < total - 1) out.push("…");
  out.push(total);
  return out;
}

const typeIcon = (t: ItemType, size = 18) =>
  t === "login" ? <IcKey size={size} /> : t === "note" ? <IcNote size={size} /> : <IcCard size={size} />;

export function Vault({
  email,
  items,
  account,
  token,
  sendContacts,
  setSendContacts,
  persistEncryptedItem,
  onUpsert,
  onTrash,
  onDelete,
  onDeleteMany,
  onImport,
  syncStatus,
  onLock,
  toast,
}: {
  email: string;
  items: VaultItem[];
  account: Account | null;
  token: string | null;
  sendContacts: Contact[];
  setSendContacts: (c: Contact[]) => void;
  persistEncryptedItem: (id: string, blob: Blob) => Promise<void>;
  onUpsert: (i: VaultItem) => Promise<boolean>;
  onTrash: (i: VaultItem) => Promise<boolean>;
  onDelete: (id: string) => Promise<boolean>;
  onDeleteMany: (ids: string[]) => Promise<boolean>;
  onImport: (r: ImportResult, onProgress: ImportProgress) => Promise<ImportOutcome>;
  syncStatus: VaultSyncStatus;
  onLock: () => void;
  toast: (m: string) => void;
}): JSX.Element {
  const [nav, setNav] = useState<Nav>("vault");
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"all" | ItemType>("all");
  const [favoritesOnly, setFavoritesOnly] = useState(false);
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null);
  const [sort, setSort] = useState<VaultSort>("favorites-recent");
  const [now, setNow] = useState(() => Date.now());
  const [editor, setEditor] = useState<null | "new" | VaultItem>(null);
  const [detail, setDetail] = useState<VaultItem | null>(null);
  const [importing, setImporting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [permanentDelete, setPermanentDelete] = useState<VaultItem | null>(null);
  const [emptyingTrash, setEmptyingTrash] = useState(false);
  const [page, setPage] = useState(1);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const firstNavRef = useRef<HTMLButtonElement>(null);
  const sidebarRef = useRef<HTMLElement>(null);
  const mobileNavWasOpen = useRef(false);

  const activeItems = useMemo(() => items.filter((item) => item.deletedAt === undefined), [items]);
  const trashedItems = useMemo(
    () => items.filter((item) => item.deletedAt !== undefined).sort((a, b) => b.deletedAt! - a.deletedAt!),
    [items]
  );
  const folders = useMemo(
    () => [...new Set(["Personal", ...activeItems.map((item) => item.folder?.trim()).filter((folder): folder is string => Boolean(folder))])]
      .sort((a, b) => a.localeCompare(b)),
    [activeItems]
  );
  const folderItems = useMemo(
    () => selectedFolder === null ? activeItems : activeItems.filter((item) => itemFolder(item) === selectedFolder),
    [activeItems, selectedFolder]
  );
  const filtered = useMemo(
    () => filterVaultItems(folderItems, tab, query, favoritesOnly, sort),
    [favoritesOnly, folderItems, query, sort, tab]
  );

  // Paginate so a 270-item vault doesn't scroll forever.
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const paged = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  useEffect(() => { setPage(1); }, [favoritesOnly, query, selectedFolder, tab]); // reset to first page on filter change

  useEffect(() => {
    if (nav !== "vault") return;
    let timer: number | undefined;
    const start = (): void => {
      window.clearInterval(timer);
      setNow(Date.now());
      if (document.visibilityState !== "hidden") {
        timer = window.setInterval(() => setNow(Date.now()), 60_000);
      }
    };
    start();
    document.addEventListener("visibilitychange", start);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", start);
    };
  }, [nav]);

  useEffect(() => {
    if (mobileNavOpen) firstNavRef.current?.focus();
    else if (mobileNavWasOpen.current) menuButtonRef.current?.focus();
    mobileNavWasOpen.current = mobileNavOpen;
  }, [mobileNavOpen]);

  useEffect(() => {
    if (!mobileNavOpen) return;
    const originalBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = originalBodyOverflow;
    };
  }, [mobileNavOpen]);

  useEffect(() => {
    function handleSearchShortcut(event: globalThis.KeyboardEvent): void {
      if (mobileNavOpen || document.querySelector('[role="dialog"]')) return;
      const target = event.target;
      const editable =
        target instanceof HTMLInputElement ||
        target instanceof HTMLTextAreaElement ||
        target instanceof HTMLSelectElement ||
        (target instanceof HTMLElement && target.isContentEditable);
      const commandK =
        event.key.toLowerCase() === "k" &&
        (event.ctrlKey || event.metaKey) &&
        !event.altKey;
      const slash =
        event.key === "/" &&
        !editable &&
        !event.ctrlKey &&
        !event.metaKey &&
        !event.altKey;
      if (!commandK && !slash) return;

      event.preventDefault();
      setSelectedFolder(null);
      setNav("vault");
      searchInputRef.current?.focus();
    }

    document.addEventListener("keydown", handleSearchShortcut);
    return () => document.removeEventListener("keydown", handleSearchShortcut);
  }, [mobileNavOpen]);

  function copy(text: string, what: string, secret = false) {
    if (secret) void copySecretWithFeedback(text, what, toast);
    else void copyWithFeedback(text, what, toast);
  }

  const counts = {
    all: folderItems.length,
    login: folderItems.filter((i) => i.type === "login").length,
    note: folderItems.filter((i) => i.type === "note").length,
    card: folderItems.filter((i) => i.type === "card").length,
    favorite: folderItems.filter((i) => i.favorite).length,
  };

  function go(n: Nav) {
    setNav(n);
    setMobileNavOpen(false);
  }

  function goFolder(folder: string | null): void {
    setSelectedFolder(folder);
    setNav("vault");
    setMobileNavOpen(false);
  }

  function handleSidebarKeyDown(event: KeyboardEvent<HTMLElement>): void {
    if (!mobileNavOpen) return;
    if (event.key === "Escape") {
      event.preventDefault();
      setMobileNavOpen(false);
      return;
    }
    if (event.key !== "Tab") return;

    const buttons = [...(sidebarRef.current?.querySelectorAll<HTMLButtonElement>("button:not([disabled])") ?? [])];
    const first = buttons[0];
    const last = buttons[buttons.length - 1];
    if (!first || !last) return;
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  return (
    <div className="shell">
      {/* ── Sidebar ── */}
      {mobileNavOpen && (
        <button
          className="sidebar-backdrop"
          type="button"
          aria-label="Dismiss navigation"
          onClick={() => setMobileNavOpen(false)}
        />
      )}
      <aside
        ref={sidebarRef}
        id="vault-navigation"
        className={`sidebar${mobileNavOpen ? " open" : ""}`}
        aria-label="Vault navigation"
        onKeyDown={handleSidebarKeyDown}
      >
        <Brand size={30} />
        <button
          ref={firstNavRef}
          className={`nav-item${nav === "vault" && selectedFolder === null ? " active" : ""}`}
          aria-current={nav === "vault" && selectedFolder === null ? "page" : undefined}
          onClick={() => goFolder(null)}
        >
          <span className="ico"><IcVault /></span> Vault
        </button>
        <button
          className={`nav-item${nav === "send" ? " active" : ""}`}
          aria-current={nav === "send" ? "page" : undefined}
          onClick={() => go("send")}
        >
          <span className="ico"><IcShared /></span> Send
        </button>
        <button
          className={`nav-item${nav === "trash" ? " active" : ""}`}
          aria-current={nav === "trash" ? "page" : undefined}
          onClick={() => go("trash")}
        >
          <span className="ico"><IcTrash /></span> Trash <span className="nav-count">{trashedItems.length}</span>
        </button>

        <div className="nav-label">Folders</div>
        {folders.map((folder) => (
          <button
            key={folder}
            className={`nav-item${nav === "vault" && selectedFolder === folder ? " active" : ""}`}
            aria-current={nav === "vault" && selectedFolder === folder ? "page" : undefined}
            onClick={() => goFolder(folder)}
          >
            <span className="ico"><IcFolder /></span> <span className="nav-text" title={folder}>{folder}</span>
          </button>
        ))}

        <div className="nav-sep" />
        <div className="nav-label">Tools</div>
        <button
          className={`nav-item${nav === "generator" ? " active" : ""}`}
          aria-current={nav === "generator" ? "page" : undefined}
          onClick={() => go("generator")}
        >
          <span className="ico"><IcGen /></span> Password Generator
        </button>
        <button
          className={`nav-item${nav === "health" ? " active" : ""}`}
          aria-current={nav === "health" ? "page" : undefined}
          onClick={() => go("health")}
        >
          <span className="ico"><IcHealth /></span> Password Health
        </button>
        <button
          className="nav-item"
          disabled
          aria-disabled="true"
          title="Requires a configured and reviewed mail relay"
        >
          <span className="ico"><IcMask /></span> Email Masking <span className="nav-status">Requires relay</span>
        </button>
        <button
          className={`nav-item${nav === "breach" ? " active" : ""}`}
          aria-current={nav === "breach" ? "page" : undefined}
          onClick={() => go("breach")}
        >
          <span className="ico"><IcBreach /></span> Breach Scanner
        </button>

        <div className="sidebar-foot">
          <div className="nav-sep" />
          <button className="nav-item" onClick={onLock}>
            <span className="ico"><IcLock /></span> Lock vault
          </button>
        </div>
      </aside>

      {/* ── Main ── */}
      <div className="main">
        <header className="topbar">
          <button
            ref={menuButtonRef}
            className="icon-btn mobile-nav-toggle"
            type="button"
            aria-label={mobileNavOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={mobileNavOpen}
            aria-controls="vault-navigation"
            onClick={() => setMobileNavOpen((open) => !open)}
          >
            <IcMenu size={20} />
          </button>
          <div className="search">
            <IcSearch size={17} />
            <input
              ref={searchInputRef}
              aria-label="Search vault items"
              placeholder="Search names, usernames, and websites"
              autoComplete="off"
              spellCheck={false}
              autoCorrect="off"
              autoCapitalize="none"
              value={query}
              onFocus={() => go("vault")}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={(event) => {
                if (event.key !== "Escape") return;
                event.preventDefault();
                if (query) setQuery("");
                else event.currentTarget.blur();
              }}
            />
            {query && (
              <button className="icon-btn search-clear" aria-label="Clear search" onClick={() => setQuery("")}>
                <IcX size={14} />
              </button>
            )}
            <kbd className="kbd" aria-label="Keyboard shortcut Control or Command K">Ctrl/⌘ K</kbd>
          </div>
          <div className="topbar-right">
            <span className={`sync-status ${syncStatus}`} role="status" aria-live="polite">
              <span className="sync-dot" aria-hidden="true" />
              {syncStatus === "saving"
                ? "Saving…"
                : syncStatus === "error"
                  ? "Sync failed"
                  : "All changes saved"}
            </span>
            <span className="pill">🔒 Zero-knowledge</span>
            <span className="faint" style={{ fontSize: 13 }}>{email}</span>
            <div className="avatar" aria-hidden="true">{(email[0] || "B").toUpperCase()}</div>
          </div>
        </header>

        <main className="content">
          {nav === "vault" && (
            <>
              <div className="page-head">
                <h2>{selectedFolder ?? "Vault"}</h2>
                <div className="right" style={{ display: "flex", gap: 8 }}>
                  <button className="btn" onClick={() => setImporting(true)}>
                    <IcUpload size={16} /> Import
                  </button>
                  {activeItems.length > 0 && (
                    <button className="btn" onClick={() => setExporting(true)}>
                      <IcDownload size={16} /> Export
                    </button>
                  )}
                  <button className="btn btn-primary" onClick={() => setEditor("new")}>
                    <IcPlus size={16} /> Create item
                  </button>
                </div>
              </div>

              <div className="tabs" aria-label="Vault filters">
                {([["all", "All Items"], ["login", "Passwords"], ["note", "Secure Notes"], ["card", "Credit Cards"]] as [typeof tab, string][]).map(
                  ([t, label]) => (
                    <button
                      key={t}
                      className={`tab${tab === t ? " active" : ""}`}
                      aria-pressed={tab === t}
                      onClick={() => setTab(t)}
                    >
                      {label} <span className="faint">{counts[t]}</span>
                    </button>
                  )
                )}
                <button
                  className={`tab${favoritesOnly ? " active" : ""}`}
                  aria-pressed={favoritesOnly}
                  onClick={() => setFavoritesOnly((active) => !active)}
                >
                  <IcStar size={14} filled={favoritesOnly} /> Favorites{" "}
                  <span className="faint">{counts.favorite}</span>
                </button>
              </div>

              <div className="vault-list-controls">
                <label>
                  <span className="faint">Sort</span>
                  <select
                    className="input sort-select"
                    aria-label="Sort vault items"
                    value={sort}
                    onChange={(event) => setSort(event.target.value as VaultSort)}
                  >
                    <option value="favorites-recent">Favorites and recent</option>
                    <option value="recent">Recently updated</option>
                    <option value="oldest">Oldest updated</option>
                    <option value="name">Name A–Z</option>
                  </select>
                </label>
              </div>

              {query.trim() && (
                <div className="search-results-status faint" role="status" aria-live="polite">
                  {filtered.length} {filtered.length === 1 ? "result" : "results"} for “{query.trim()}”
                </div>
              )}

              {filtered.length === 0 ? (
                <div className="empty">
                  <div className="big">{folderItems.length === 0 && !selectedFolder ? <IcVault size={54} /> : <IcSearch size={54} />}</div>
                  <div style={{ fontSize: 16, color: "var(--text-dim)" }}>
                    {activeItems.length === 0
                      ? "No items yet"
                      : selectedFolder && folderItems.length === 0
                        ? `No items in ${selectedFolder}`
                      : favoritesOnly && !query.trim() && tab === "all"
                        ? "No favorite items"
                        : "No matching items"}
                  </div>
                  <div style={{ marginTop: 6 }}>
                    {activeItems.length === 0
                      ? "Create your first item to get started."
                      : selectedFolder && folderItems.length === 0
                        ? "Assign this folder while creating or editing an item."
                      : favoritesOnly && !query.trim() && tab === "all"
                        ? "Mark an item as a favorite to see it here."
                        : "Try another search or item type."}
                  </div>
                  {activeItems.length > 0 && filtered.length === 0 && (
                    <button
                      className="btn"
                      style={{ marginTop: 16 }}
                      onClick={() => {
                        setQuery("");
                        setTab("all");
                        setFavoritesOnly(false);
                        searchInputRef.current?.focus();
                      }}
                    >
                      Clear filters
                    </button>
                  )}
                </div>
              ) : (
                <div className="list">
                  <div className="list-head"><span>Title</span><span>Last updated</span><span style={{ textAlign: "right" }}>Actions</span></div>
                  {paged.map((i) => (
                    <div className="row" key={i.id}>
                      <button
                        className="row-open"
                        aria-label={`Open ${i.title}`}
                        onClick={() => setDetail(i)}
                      >
                        <span className="title">
                          <Favicon item={i} size={36} />
                          <span style={{ minWidth: 0 }}>
                            <span className="ttl">{i.title}</span>
                            <span className="sub">
                              {i.type === "login" ? (
                                i.username || i.url || "—"
                              ) : i.type === "card" ? (
                                <CardSubtitle item={i} />
                              ) : (
                                TYPE_LABEL[i.type]
                              )}
                            </span>
                          </span>
                        </span>
                        <time
                          className="when"
                          dateTime={new Date(i.updatedAt).toISOString()}
                          title={new Date(i.updatedAt).toLocaleString()}
                        >
                          {relativeItemTime(i.updatedAt, now)}
                        </time>
                      </button>
                      <div className="actions">
                        <button
                          className={`icon-btn${i.favorite ? " fav-on" : ""}`}
                          aria-label={`${i.favorite ? "Remove" : "Add"} ${i.title} ${i.favorite ? "from" : "to"} favorites`}
                          aria-pressed={Boolean(i.favorite)}
                          style={i.favorite ? { color: "var(--warn)" } : undefined}
                          onClick={() => void onUpsert({ ...i, favorite: !i.favorite })}
                        >
                          <IcStar size={16} filled={Boolean(i.favorite)} />
                        </button>
                        {i.type === "login" && i.password && (
                          <button className="icon-btn" aria-label={`Copy password for ${i.title}`} onClick={() => copy(i.password!, "Password", true)}>
                            <IcCopy size={16} />
                          </button>
                        )}
                        <button className="icon-btn" aria-label={`Edit ${i.title}`} onClick={() => setEditor(i)}>
                          <IcEdit size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {pageCount > 1 && (
                <div className="pager">
                  <span className="pager-info">
                    {(safePage - 1) * PAGE_SIZE + 1}–{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length}
                  </span>
                  <div className="pager-btns">
                    <button className="pg" disabled={safePage === 1} onClick={() => setPage(safePage - 1)} aria-label="Previous page">‹</button>
                    {pageNumbers(safePage, pageCount).map((p, idx) =>
                      p === "…" ? (
                        <span key={`e${idx}`} className="pg-gap">…</span>
                      ) : (
                        <button
                          key={p}
                          className={`pg${p === safePage ? " active" : ""}`}
                          aria-label={`Page ${p}`}
                          aria-current={p === safePage ? "page" : undefined}
                          onClick={() => setPage(p)}
                        >
                          {p}
                        </button>
                      )
                    )}
                    <button className="pg" disabled={safePage === pageCount} onClick={() => setPage(safePage + 1)} aria-label="Next page">›</button>
                  </div>
                </div>
              )}
            </>
          )}

          {nav === "generator" && (
            <>
              <div className="page-head"><h2>Password Generator</h2></div>
              <div className="card-section"><Generator toast={toast} /></div>
            </>
          )}

          {nav === "health" && <Health items={activeItems} onOpen={(i) => setDetail(i)} />}

          {nav === "breach" && <BreachScanner items={activeItems} onOpen={(i) => setDetail(i)} />}

          {nav === "trash" && (
            <>
              <div className="page-head">
                <h2>Trash</h2>
                {trashedItems.length > 0 && (
                  <button className="btn btn-danger" onClick={() => setEmptyingTrash(true)}>
                    <IcTrash size={16} /> Empty trash
                  </button>
                )}
              </div>
              {trashedItems.length === 0 ? (
                <div className="empty">
                  <div className="big"><IcTrash size={54} /></div>
                  <div style={{ fontSize: 16, color: "var(--text-dim)" }}>Trash is empty</div>
                  <div style={{ marginTop: 6 }}>Deleted items will appear here until permanently removed.</div>
                </div>
              ) : (
                <div className="list">
                  <div className="list-head"><span>Title</span><span>Deleted</span><span style={{ textAlign: "right" }}>Actions</span></div>
                  {trashedItems.map((item) => (
                    <div className="row" key={item.id}>
                      <div className="row-open">
                        <span className="title">
                          <Favicon item={item} size={36} />
                          <span style={{ minWidth: 0 }}>
                            <span className="ttl">{item.title}</span>
                            <span className="sub">{item.folder || TYPE_LABEL[item.type]}</span>
                          </span>
                        </span>
                        <time className="when" dateTime={new Date(item.deletedAt!).toISOString()}>
                          {relativeItemTime(item.deletedAt!, now)}
                        </time>
                      </div>
                      <div className="actions">
                        <button
                          className="btn btn-ghost"
                          onClick={() => void onUpsert({ ...item, deletedAt: undefined, updatedAt: Date.now() })}
                        >
                          Restore
                        </button>
                        <button className="icon-btn" aria-label={`Delete ${item.title} permanently`} onClick={() => setPermanentDelete(item)}>
                          <IcTrash size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          )}

          {nav === "send" && account && token && (
            <Send
              account={account}
              token={token}
              contacts={sendContacts}
              setContacts={setSendContacts}
              persistEncryptedItem={persistEncryptedItem}
              onLock={onLock}
              toast={toast}
            />
          )}

        </main>
      </div>

      {editor && (
        <ItemEditor
          initial={editor === "new" ? null : editor}
          folders={folders}
          defaultFolder={selectedFolder ?? undefined}
          onClose={() => setEditor(null)}
          onSave={async (i) => {
            const saved = await onUpsert(i);
            if (saved) {
              setEditor(null);
              toast("Item saved");
            }
            return saved;
          }}
        />
      )}

      {detail && (
        <ItemDetailView
          item={detail}
          onClose={() => setDetail(null)}
          onEdit={() => { setEditor(detail); setDetail(null); }}
          onTrash={async () => {
            if (await onTrash(detail)) {
              setDetail(null);
              toast("Item moved to trash");
              return true;
            }
            return false;
          }}
          copy={copy}
        />
      )}

      {importing && (
        <ImportModal
          existingItems={items}
          onClose={() => setImporting(false)}
          onImport={async (result, onProgress) => {
            const outcome = await onImport(result, onProgress);
            setNav("vault");
            setTab("all");
            return outcome;
          }}
        />
      )}

      {exporting && (
        <ConfirmDialog
          title="Export vault?"
          confirmLabel={`Export ${activeItems.length} ${activeItems.length === 1 ? "item" : "items"}`}
          pendingLabel="Exporting…"
          onClose={() => setExporting(false)}
          onConfirm={async () => {
            const ok = downloadCsv(itemsToCsv(activeItems), exportFilename(new Date()));
            toast(ok ? "Vault exported" : "Export failed");
            return ok;
          }}
        >
          The exported CSV contains every password, card number and note in{" "}
          <b>unencrypted plaintext</b>. Save it only to a location you trust, and
          delete it as soon as you are done.
        </ConfirmDialog>
      )}

      {permanentDelete && (
        <ConfirmDialog
          title={`Delete ${permanentDelete.title} permanently?`}
          confirmLabel="Delete permanently"
          pendingLabel="Deleting…"
          onClose={() => setPermanentDelete(null)}
          onConfirm={async () => {
            const deleted = await onDelete(permanentDelete.id);
            if (deleted) setPermanentDelete(null);
            return deleted;
          }}
        >
          This permanently removes the encrypted item. This action cannot be undone.
        </ConfirmDialog>
      )}

      {emptyingTrash && (
        <ConfirmDialog
          title="Empty trash?"
          confirmLabel={`Delete ${trashedItems.length} permanently`}
          pendingLabel="Deleting…"
          onClose={() => setEmptyingTrash(false)}
          onConfirm={async () => {
            const deleted = await onDeleteMany(trashedItems.map((item) => item.id));
            if (deleted) setEmptyingTrash(false);
            return deleted;
          }}
        >
          Every item in trash will be permanently removed. This action cannot be undone.
        </ConfirmDialog>
      )}
    </div>
  );
}

// ── Item detail overlay ──
function ItemDetailView({
  item, onClose, onEdit, onTrash, copy,
}: {
  item: VaultItem;
  onClose: () => void;
  onEdit: () => void;
  onTrash: () => Promise<boolean>;
  copy: (t: string, w: string, secret?: boolean) => void;
}): JSX.Element {
  const [revealed, setRevealed] = useState<Set<string>>(() => new Set());
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const concealTimers = useRef<Map<string, number>>(new Map());
  const rows: [string, string | undefined, boolean][] =
    item.type === "login"
      ? [["Username", item.username, false], ["Password", item.password, true], ["Website", item.url, false]]
      : item.type === "card"
        ? [["Cardholder", item.cardholderName, false], ["Number", item.cardNumber, true], ["Expiry", item.cardExp, false], ["CVV", item.cardCvv, true]]
        : [];
  const websiteUrl = safeWebsiteUrl(item.url);

  function conceal(key: string): void {
    const timer = concealTimers.current.get(key);
    if (timer !== undefined) window.clearTimeout(timer);
    concealTimers.current.delete(key);
    setRevealed((current) => {
      if (!current.has(key)) return current;
      const next = new Set(current);
      next.delete(key);
      return next;
    });
  }

  function concealAll(): void {
    concealTimers.current.forEach((timer) => window.clearTimeout(timer));
    concealTimers.current.clear();
    setRevealed(new Set());
  }

  function toggleReveal(key: string): void {
    if (revealed.has(key)) {
      conceal(key);
      return;
    }
    setRevealed((current) => new Set(current).add(key));
    concealTimers.current.set(key, window.setTimeout(() => conceal(key), SECRET_REVEAL_MS));
  }

  // Concealing is not locking. App.tsx deliberately refuses to auto-lock on
  // window `blur` because that event fires for the address bar, extensions,
  // autofill and screenshot tools — locking there would evict the user
  // constantly. Re-hiding an on-screen secret costs one click to undo, so the
  // same event is worth acting on here: the moment this window stops being
  // the focused one, a shoulder-surfer, a screen recorder or a screen share
  // of the *other* window can still be pointed at this one.
  useEffect(() => {
    const timers = concealTimers.current;
    const onVisibilityChange = (): void => {
      if (document.visibilityState === "hidden") concealAll();
    };
    const onWindowBlur = (): void => concealAll();
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("blur", onWindowBlur);
    window.addEventListener("pagehide", onWindowBlur);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("blur", onWindowBlur);
      window.removeEventListener("pagehide", onWindowBlur);
      timers.forEach((timer) => window.clearTimeout(timer));
      timers.clear();
    };
  }, []);

  return (
    <>
      <Dialog
        title={item.title}
        onClose={onClose}
        inactive={confirmingDelete}
        headerLeading={<Favicon item={item} size={32} />}
        headerMeta={<span className="pill" style={{ marginLeft: 8 }}>{typeIcon(item.type, 12)} {TYPE_LABEL[item.type]}</span>}
        footer={
          <>
            <button className="btn btn-danger" onClick={() => setConfirmingDelete(true)}>
              <IcTrash size={16} /> Move to trash
            </button>
            <span className="spacer" />
            <button className="btn btn-primary" onClick={onEdit}>
              <IcEdit size={16} /> Edit
            </button>
          </>
        }
      >
          {rows.filter(([, v]) => v).map(([k, v, secret]) => {
            const isRevealed = revealed.has(k);
            return (
              <div className="row-copy" key={k}>
                <span className="k">{k}</span>
                <span className="v mono">{secret && !isRevealed ? "•".repeat(Math.min(14, (v || "").length)) : v}</span>
                {secret && (
                  <button
                    className="icon-btn"
                    aria-label={`${isRevealed ? "Hide" : "Reveal"} ${k.toLowerCase()}`}
                    aria-pressed={isRevealed}
                    onClick={() => toggleReveal(k)}
                  >
                    <IcEye size={16} />
                  </button>
                )}
                {k === "Website" && websiteUrl && (
                  <a
                    className="icon-btn"
                    href={websiteUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    referrerPolicy="no-referrer"
                    aria-label="Open website in a new tab"
                  >
                    <IcExternal size={16} />
                  </a>
                )}
                <button className="icon-btn" aria-label={`Copy ${k.toLowerCase()}`} onClick={() => copy(v!, k, secret)}><IcCopy size={16} /></button>
              </div>
            );
          })}
          {item.notes && (
            <div className="row-copy" style={{ alignItems: "flex-start" }}>
              <span className="k">Notes</span>
              <span className="v" style={{ whiteSpace: "pre-wrap" }}>{item.notes}</span>
            </div>
          )}
          {item.folder && (
            <div className="row-copy">
              <span className="k">Folder</span>
              <span className="v">{item.folder}</span>
            </div>
          )}
      </Dialog>
      {confirmingDelete && (
        <ConfirmDialog
          title={`Move ${item.title} to trash?`}
          confirmLabel="Move to trash"
          pendingLabel="Moving…"
          onClose={() => setConfirmingDelete(false)}
          onConfirm={onTrash}
        >
          The item will stop appearing in your vault and extension, but can be restored from Trash.
        </ConfirmDialog>
      )}
    </>
  );
}

// ── Password Health ──
function Health({ items, onOpen }: { items: VaultItem[]; onOpen: (i: VaultItem) => void }): JSX.Element {
  const analysis = useMemo(() => analyzePasswordHealth(items, Date.now()), [items]);
  const score = analysis.score;
  const scoreColor =
    score === null
      ? "var(--text-faint)"
      : score >= 80
        ? "var(--ok)"
        : score >= 50
          ? "var(--warn)"
          : "var(--danger)";

  const Finding = ({ item, detail }: { item: VaultItem; detail: string }) => (
    <button className="row-copy health-row" onClick={() => onOpen(item)}>
      <Favicon item={item} size={28} />
      <span className="v">{item.title}</span>
      <span className="faint health-meta">{detail}</span>
    </button>
  );

  const WeakSection = () =>
    analysis.weakItems.length === 0 ? null : (
      <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
        <div className="health-section-title" style={{ color: "var(--danger)" }}>
          Weak passwords · {analysis.weakItems.length}
        </div>
        {analysis.weakItems.map((item) => {
          const assessment = analysis.assessments.get(item.id)!;
          return (
            <Finding
              key={item.id}
              item={item}
              detail={`${assessment.label} · ${assessment.reasons[0]}`}
            />
          );
        })}
      </div>
    );

  return (
    <>
      <div className="page-head"><h2>Password Health</h2></div>
      <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
          <div style={{ fontSize: 40, fontWeight: 800, color: scoreColor }}>{score ?? "—"}</div>
          <div className="muted">{score === null ? "not scored" : "vault health score"}</div>
        </div>
        {score !== null && (
          <div
            className="strength"
            role="progressbar"
            aria-label="Vault health score"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={score}
            style={{ marginTop: 10 }}
          >
            <i style={{ width: `${score}%`, background: scoreColor }} />
          </div>
        )}
        <div className="faint" style={{ marginTop: 10, fontSize: 13 }}>
          {analysis.assessedCount}/{analysis.loginCount} login passwords assessed · {analysis.weakItems.length} weak · {analysis.reusedGroups.length} reused {analysis.reusedGroups.length === 1 ? "group" : "groups"} · {analysis.oldItems.length} old
        </div>
        <div className="faint" style={{ marginTop: 6, fontSize: 12 }}>
          Offline analysis only: length, character variety, obvious patterns, and exact reuse.
        </div>
      </div>
      <WeakSection />
      {analysis.reusedGroups.length > 0 && (
        <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
          <div className="health-section-title" style={{ color: "var(--warn)" }}>
            Reused password groups · {analysis.reusedGroups.length}
          </div>
          {analysis.reusedGroups.map((group, index) => (
            <div className="reuse-group" key={group.items.map((item) => item.id).join(":")}>
              <div className="faint reuse-group-title">
                Group {index + 1} · {group.items.length} accounts
              </div>
              {group.items.map((item) => (
                <Finding key={item.id} item={item} detail={item.username || "No username"} />
              ))}
            </div>
          ))}
        </div>
      )}
      {analysis.oldItems.length > 0 && (
        <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
          <div className="health-section-title" style={{ color: "var(--warn)" }}>
            Old passwords · {analysis.oldItems.length}
          </div>
          {analysis.oldItems.map((item) => (
            <Finding
              key={item.id}
              item={item}
              detail={`Unchanged for ${Math.floor((Date.now() - passwordAgeReference(item)) / 86_400_000)} days`}
            />
          ))}
        </div>
      )}
      {analysis.assessedCount === 0 && (
        <div className="card-section" style={{ maxWidth: 640 }}>
          <span className="muted">Add a login with a password to calculate vault health.</span>
        </div>
      )}
      {analysis.assessedCount > 0 && analysis.atRiskItems.length === 0 && (
        <div className="card-section" style={{ maxWidth: 640 }}>
          <span className="muted">No weak, reused or old passwords found by the offline checks. 🎉</span>
        </div>
      )}
    </>
  );
}
