import { useMemo, useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { Generator } from "../components/Generator";
import { ItemEditor } from "../components/ItemEditor";
import { ImportModal } from "../components/ImportModal";
import {
  IcBreach, IcCard, IcCopy, IcEdit, IcEye, IcFolder, IcGen, IcHealth, IcKey,
  IcLock, IcMask, IcNote, IcPlus, IcSearch, IcShared, IcTrash, IcUpload, IcVault, IcX,
} from "../components/icons";
import { itemColor, TYPE_LABEL, type ItemType, type VaultItem } from "../lib/types";
import { strength } from "../lib/generator";
import type { ImportResult } from "../lib/import";

type Nav = "vault" | "generator" | "health" | "soon";

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
  onUpsert,
  onDelete,
  onImport,
  onLock,
  toast,
}: {
  email: string;
  items: VaultItem[];
  onUpsert: (i: VaultItem) => void;
  onDelete: (id: string) => void;
  onImport: (r: ImportResult) => void;
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

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items
      .filter((i) => tab === "all" || i.type === tab)
      .filter((i) => !q || i.title.toLowerCase().includes(q) || (i.username ?? "").toLowerCase().includes(q) || (i.url ?? "").toLowerCase().includes(q))
      .sort((a, b) => b.updatedAt - a.updatedAt);
  }, [items, tab, query]);

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
      <aside className="sidebar">
        <Brand size={30} />
        <button className={`nav-item${nav === "vault" ? " active" : ""}`} onClick={() => go("vault")}>
          <span className="ico"><IcVault /></span> Vault
        </button>
        <button className="nav-item" onClick={() => go("soon", "Shared items")}>
          <span className="ico"><IcShared /></span> Shared
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
        <button className={`nav-item${nav === "generator" ? " active" : ""}`} onClick={() => go("generator")}>
          <span className="ico"><IcGen /></span> Password Generator
        </button>
        <button className={`nav-item${nav === "health" ? " active" : ""}`} onClick={() => go("health")}>
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
        <div className="topbar">
          <div className="search">
            <IcSearch size={17} />
            <input placeholder="Search all items" value={query} onChange={(e) => setQuery(e.target.value)} />
            <span className="kbd">Ctrl F</span>
          </div>
          <div className="topbar-right">
            <span className="pill">🔒 Zero-knowledge</span>
            <span className="faint" style={{ fontSize: 13 }}>{email}</span>
            <div className="avatar" title={email}>{(email[0] || "B").toUpperCase()}</div>
          </div>
        </div>

        <div className="content">
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

              <div className="tabs">
                {([["all", "All Items"], ["login", "Passwords"], ["note", "Secure Notes"], ["card", "Credit Cards"]] as [typeof tab, string][]).map(
                  ([t, label]) => (
                    <button key={t} className={`tab${tab === t ? " active" : ""}`} onClick={() => setTab(t)}>
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
                  {filtered.map((i) => (
                    <div className="row" key={i.id} onClick={() => setDetail(i)}>
                      <div className="title">
                        <div className="fav-ico" style={{ background: itemColor(i.title) }}>{(i.title[0] || "?").toUpperCase()}</div>
                        <div style={{ minWidth: 0 }}>
                          <div className="ttl">{i.title}</div>
                          <div className="sub">{i.type === "login" ? i.username || i.url || "—" : TYPE_LABEL[i.type]}</div>
                        </div>
                      </div>
                      <div className="when">{timeAgo(i.updatedAt)}</div>
                      <div className="actions">
                        {i.type === "login" && i.password && (
                          <button className="icon-btn" title="Copy password" onClick={(e) => { e.stopPropagation(); copy(i.password!, "Password"); }}>
                            <IcCopy size={16} />
                          </button>
                        )}
                        <button className="icon-btn" title="Edit" onClick={(e) => { e.stopPropagation(); setEditor(i); }}>
                          <IcEdit size={16} />
                        </button>
                      </div>
                    </div>
                  ))}
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

          {nav === "soon" && (
            <div className="empty">
              <div className="big"><IcGen size={54} /></div>
              <div style={{ fontSize: 16, color: "var(--text-dim)" }}>{soonLabel}</div>
              <div style={{ marginTop: 6 }}>Coming soon.</div>
            </div>
          )}
        </div>
      </div>

      {editor && (
        <ItemEditor
          initial={editor === "new" ? null : editor}
          onClose={() => setEditor(null)}
          onSave={(i) => { onUpsert(i); setEditor(null); toast("Item saved"); }}
        />
      )}

      {detail && (
        <ItemDetailView
          item={detail}
          onClose={() => setDetail(null)}
          onEdit={() => { setEditor(detail); setDetail(null); }}
          onDelete={() => { onDelete(detail.id); setDetail(null); toast("Item deleted"); }}
          copy={copy}
        />
      )}

      {importing && (
        <ImportModal
          onClose={() => setImporting(false)}
          onImport={(r) => { onImport(r); setImporting(false); setNav("vault"); setTab("all"); }}
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
  onDelete: () => void;
  copy: (t: string, w: string) => void;
}): JSX.Element {
  const [reveal, setReveal] = useState(false);
  const rows: [string, string | undefined, boolean][] =
    item.type === "login"
      ? [["Username", item.username, false], ["Password", item.password, true], ["Website", item.url, false]]
      : item.type === "card"
        ? [["Number", item.cardNumber, true], ["Expiry", item.cardExp, false], ["CVV", item.cardCvv, true]]
        : [];

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="fav-ico" style={{ background: itemColor(item.title), width: 32, height: 32 }}>{(item.title[0] || "?").toUpperCase()}</div>
          <h3>{item.title}</h3>
          <span className="pill" style={{ marginLeft: 8 }}>{typeIcon(item.type, 12)} {TYPE_LABEL[item.type]}</span>
          <button className="icon-btn x" onClick={onClose}><IcX size={18} /></button>
        </div>
        <div className="modal-body">
          {rows.filter(([, v]) => v).map(([k, v, secret]) => (
            <div className="row-copy" key={k}>
              <span className="k">{k}</span>
              <span className="v mono">{secret && !reveal ? "•".repeat(Math.min(14, (v || "").length)) : v}</span>
              {secret && (
                <button className="icon-btn" title="Reveal" onClick={() => setReveal((r) => !r)}><IcEye size={16} /></button>
              )}
              <button className="icon-btn" title="Copy" onClick={() => copy(v!, k)}><IcCopy size={16} /></button>
            </div>
          ))}
          {item.notes && (
            <div className="row-copy" style={{ alignItems: "flex-start" }}>
              <span className="k">Notes</span>
              <span className="v" style={{ whiteSpace: "pre-wrap" }}>{item.notes}</span>
            </div>
          )}
        </div>
        <div className="modal-foot">
          <button className="btn btn-danger" onClick={onDelete}><IcTrash size={16} /> Delete</button>
          <span className="spacer" />
          <button className="btn btn-primary" onClick={onEdit}><IcEdit size={16} /> Edit</button>
        </div>
      </div>
    </div>
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
          <div className="row-copy" key={i.id} style={{ cursor: "pointer" }} onClick={() => onOpen(i)}>
            <div className="fav-ico" style={{ background: itemColor(i.title), width: 28, height: 28, fontSize: 12 }}>{(i.title[0] || "?").toUpperCase()}</div>
            <span className="v">{i.title}</span>
            <span className="faint" style={{ fontSize: 12 }}>{i.username}</span>
          </div>
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
