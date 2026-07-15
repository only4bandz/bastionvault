import { useEffect, useMemo, useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { Generator } from "../components/Generator";
import { ItemEditor } from "../components/ItemEditor";
import { ImportModal } from "../components/ImportModal";
import { Dialog } from "../components/Dialog";
import { Favicon } from "../components/Favicon";
import {
  IcBreach, IcCard, IcCopy, IcEdit, IcEye, IcFolder, IcGen, IcHealth, IcKey,
  IcLock, IcMask, IcNote, IcPlus, IcSearch, IcShared, IcTrash, IcUpload, IcVault,
} from "../components/icons";
import { TYPE_LABEL, type ItemType, type VaultItem } from "../lib/types";
import { strength } from "../lib/generator";
import { lookupBin } from "../lib/bin";
import type { ImportResult } from "../lib/import";
import type { Account } from "../lib/wasm";
import type { Contact } from "../lib/send";
import type { Blob } from "../lib/api";
import { Send } from "./Send";

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

type Nav = "vault" | "generator" | "health" | "send" | "soon";

const PAGE_SIZE = 50;

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

function timeAgo(ts: number): string {
  const d = Math.floor((Date.now() - ts) / 1000);
  if (d < 60) return "just now";
  if (d < 3600) return `${Math.floor(d / 60)}m ago`;
  if (d < 86400) return `${Math.floor(d / 3600)}h ago`;
  return `${Math.floor(d / 86400)}d ago`;
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
  onDelete,
  onImport,
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
  onDelete: (id: string) => Promise<boolean>;
  onImport: (r: ImportResult) => Promise<void>;
  onLock: () => void;
  toast: (m: string) => void;
}): JSX.Element {
  const [nav, setNav] = useState<Nav>("vault");
  const [soonLabel, setSoonLabel] = useState("");
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"all" | ItemType>("all");
  const [editor, setEditor] = useState<null | "new" | VaultItem>(null);
  const [detail, setDetail] = useState<VaultItem | null>(null);
  const [importing, setImporting] = useState(false);
  const [page, setPage] = useState(1);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items
      .filter((i) => tab === "all" || i.type === tab)
      .filter((i) => !q || i.title.toLowerCase().includes(q) || (i.username ?? "").toLowerCase().includes(q) || (i.url ?? "").toLowerCase().includes(q))
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }, [items, tab, query]);

  // Paginate so a 270-item vault doesn't scroll forever.
  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, pageCount);
  const paged = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);
  useEffect(() => { setPage(1); }, [query, tab]); // reset to first page on filter change

  function copy(text: string, what: string) {
    navigator.clipboard?.writeText(text);
    toast(`${what} copied`);
  }

  const counts = {
    all: items.length,
    login: items.filter((i) => i.type === "login").length,
    note: items.filter((i) => i.type === "note").length,
    card: items.filter((i) => i.type === "card").length,
  };

  function go(n: Nav, label = "") {
    setNav(n);
    setSoonLabel(label);
  }

  return (
    <div className="shell">
      {/* ── Sidebar ── */}
      <aside className="sidebar" aria-label="Vault navigation">
        <Brand size={30} />
        <button
          className={`nav-item${nav === "vault" ? " active" : ""}`}
          aria-current={nav === "vault" ? "page" : undefined}
          onClick={() => go("vault")}
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
        <button className="nav-item" onClick={() => go("soon", "Trash")}>
          <span className="ico"><IcTrash /></span> Trash
        </button>

        <div className="nav-label">Folders</div>
        <button className="nav-item" onClick={() => go("soon", "Folders")}>
          <span className="ico"><IcFolder /></span> Personal
        </button>

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
        <button className="nav-item" onClick={() => go("soon", "Email Masking")}>
          <span className="ico"><IcMask /></span> Email Masking
        </button>
        <button className="nav-item" onClick={() => go("soon", "Data Breach Scanner")}>
          <span className="ico"><IcBreach /></span> Data Breach Scanner
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
          <div className="search">
            <IcSearch size={17} />
            <input aria-label="Search vault items" placeholder="Search all items" value={query} onChange={(e) => setQuery(e.target.value)} />
            <span className="kbd">Ctrl F</span>
          </div>
          <div className="topbar-right">
            <span className="pill">🔒 Zero-knowledge</span>
            <span className="faint" style={{ fontSize: 13 }}>{email}</span>
            <div className="avatar" aria-hidden="true">{(email[0] || "B").toUpperCase()}</div>
          </div>
        </header>

        <main className="content">
          {nav === "vault" && (
            <>
              <div className="page-head">
                <h2>Vault</h2>
                <div className="right" style={{ display: "flex", gap: 8 }}>
                  <button className="btn" onClick={() => setImporting(true)}>
                    <IcUpload size={16} /> Import
                  </button>
                  <button className="btn btn-primary" onClick={() => setEditor("new")}>
                    <IcPlus size={16} /> Create item
                  </button>
                </div>
              </div>

              <div className="tabs" aria-label="Vault item type">
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
              </div>

              {filtered.length === 0 ? (
                <div className="empty">
                  <div className="big"><IcVault size={54} /></div>
                  <div style={{ fontSize: 16, color: "var(--text-dim)" }}>No items yet</div>
                  <div style={{ marginTop: 6 }}>Create your first item to get started.</div>
                </div>
              ) : (
                <div className="list">
                  <div className="list-head"><span>Title</span><span>Last updated</span><span style={{ textAlign: "right" }}>Type</span></div>
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
                        <span className="when">{timeAgo(i.updatedAt)}</span>
                      </button>
                      <div className="actions">
                        {i.type === "login" && i.password && (
                          <button className="icon-btn" aria-label={`Copy password for ${i.title}`} onClick={() => copy(i.password!, "Password")}>
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

          {nav === "health" && <Health items={items} onOpen={(i) => setDetail(i)} />}

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

          {nav === "soon" && (
            <div className="empty">
              <div className="big"><IcGen size={54} /></div>
              <div style={{ fontSize: 16, color: "var(--text-dim)" }}>{soonLabel}</div>
              <div style={{ marginTop: 6 }}>Coming soon.</div>
            </div>
          )}
        </main>
      </div>

      {editor && (
        <ItemEditor
          initial={editor === "new" ? null : editor}
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
          onDelete={async () => {
            if (await onDelete(detail.id)) {
              setDetail(null);
              toast("Item deleted");
              return true;
            }
            return false;
          }}
          copy={copy}
        />
      )}

      {importing && (
        <ImportModal
          onClose={() => setImporting(false)}
          onImport={(r) => {
            void onImport(r);
            setImporting(false);
            setNav("vault");
            setTab("all");
          }}
        />
      )}
    </div>
  );
}

// ── Item detail overlay ──
function ItemDetailView({
  item, onClose, onEdit, onDelete, copy,
}: {
  item: VaultItem;
  onClose: () => void;
  onEdit: () => void;
  onDelete: () => Promise<boolean>;
  copy: (t: string, w: string) => void;
}): JSX.Element {
  const [reveal, setReveal] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const rows: [string, string | undefined, boolean][] =
    item.type === "login"
      ? [["Username", item.username, false], ["Password", item.password, true], ["Website", item.url, false]]
      : item.type === "card"
        ? [["Number", item.cardNumber, true], ["Expiry", item.cardExp, false], ["CVV", item.cardCvv, true]]
        : [];

  return (
    <Dialog
      title={item.title}
      onClose={onClose}
      closeDisabled={deleting}
      headerLeading={<Favicon item={item} size={32} />}
      headerMeta={<span className="pill" style={{ marginLeft: 8 }}>{typeIcon(item.type, 12)} {TYPE_LABEL[item.type]}</span>}
      footer={
        <>
          <button
            className="btn btn-danger"
            disabled={deleting}
            onClick={() => {
              setDeleting(true);
              void onDelete().then((deleted) => {
                if (!deleted) setDeleting(false);
              });
            }}
          >
            <IcTrash size={16} /> {deleting ? "Deleting…" : "Delete"}
          </button>
          <span className="spacer" />
          <button className="btn btn-primary" onClick={onEdit} disabled={deleting}>
            <IcEdit size={16} /> Edit
          </button>
        </>
      }
    >
          {rows.filter(([, v]) => v).map(([k, v, secret]) => (
            <div className="row-copy" key={k}>
              <span className="k">{k}</span>
              <span className="v mono">{secret && !reveal ? "•".repeat(Math.min(14, (v || "").length)) : v}</span>
              {secret && (
                <button
                  className="icon-btn"
                  aria-label={`${reveal ? "Hide" : "Reveal"} ${k.toLowerCase()}`}
                  aria-pressed={reveal}
                  onClick={() => setReveal((r) => !r)}
                >
                  <IcEye size={16} />
                </button>
              )}
              <button className="icon-btn" aria-label={`Copy ${k.toLowerCase()}`} onClick={() => copy(v!, k)}><IcCopy size={16} /></button>
            </div>
          ))}
          {item.notes && (
            <div className="row-copy" style={{ alignItems: "flex-start" }}>
              <span className="k">Notes</span>
              <span className="v" style={{ whiteSpace: "pre-wrap" }}>{item.notes}</span>
            </div>
          )}
    </Dialog>
  );
}

// ── Password Health ──
function Health({ items, onOpen }: { items: VaultItem[]; onOpen: (i: VaultItem) => void }): JSX.Element {
  const logins = items.filter((i) => i.type === "login" && i.password);
  const counts = new Map<string, number>();
  logins.forEach((i) => counts.set(i.password!, (counts.get(i.password!) || 0) + 1));
  const weak = logins.filter((i) => strength(i.password!).score < 2);
  const reused = logins.filter((i) => (counts.get(i.password!) || 0) > 1);
  const score = logins.length === 0 ? 100 : Math.round(100 * (1 - (weak.length + reused.length) / (logins.length * 2)));

  const Section = ({ title, list, color }: { title: string; list: VaultItem[]; color: string }) =>
    list.length === 0 ? null : (
      <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
        <div style={{ fontWeight: 700, marginBottom: 10, color }}>{title} · {list.length}</div>
        {list.map((i) => (
          <button className="row-copy health-row" key={i.id} onClick={() => onOpen(i)}>
            <Favicon item={i} size={28} />
            <span className="v">{i.title}</span>
            <span className="faint" style={{ fontSize: 12 }}>{i.username}</span>
          </button>
        ))}
      </div>
    );

  return (
    <>
      <div className="page-head"><h2>Password Health</h2></div>
      <div className="card-section" style={{ maxWidth: 640, marginBottom: 16 }}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 12 }}>
          <div style={{ fontSize: 40, fontWeight: 800, color: score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--danger)" }}>{score}</div>
          <div className="muted">vault health score</div>
        </div>
        <div className="strength" style={{ marginTop: 10 }}>
          <i style={{ width: `${score}%`, background: score >= 80 ? "var(--ok)" : score >= 50 ? "var(--warn)" : "var(--danger)" }} />
        </div>
        <div className="faint" style={{ marginTop: 10, fontSize: 13 }}>
          {logins.length} logins · {weak.length} weak · {reused.length} reused
        </div>
      </div>
      <Section title="Weak passwords" list={weak} color="var(--danger)" />
      <Section title="Reused passwords" list={reused} color="var(--warn)" />
      {weak.length === 0 && reused.length === 0 && (
        <div className="card-section" style={{ maxWidth: 640 }}>
          <span className="muted">No weak or reused passwords found. 🎉</span>
        </div>
      )}
    </>
  );
}
