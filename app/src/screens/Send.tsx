import { useEffect, useState, type JSX } from "react";
import type { Account } from "../lib/wasm";
import {
  sendState,
  sendEnable,
  saveContacts,
  resolveContact,
  composeNote,
  openMessage,
  inboxList,
  inboxDelete,
  type Contact,
  type Resolved,
  type Opened,
  type InboxItem,
} from "../lib/send";
import { IcCopy, IcShared, IcPlus, IcTrash, IcEdit } from "../components/icons";

type View = "home" | "contacts" | "add" | "verify" | "compose" | "inbox";

/** Redact the middle of a long Bastion address: NXKXR2TT…VWY5RI. */
const shortId = (id: string): string => (id.length > 16 ? `${id.slice(0, 8)}…${id.slice(-6)}` : id);
/** A contact's label: its name, or the redacted address when unnamed. */
const contactLabel = (c: { display: string; bastion_id: string }): string =>
  c.display === c.bastion_id ? shortId(c.bastion_id) : c.display;

export function Send({
  account,
  token,
  contacts,
  setContacts,
  toast,
}: {
  account: Account;
  token: string;
  contacts: Contact[];
  setContacts: (c: Contact[]) => void;
  toast: (m: string) => void;
}): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [bastionId, setBastionId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<View>("home");
  const [resolved, setResolved] = useState<Resolved | null>(null);
  const [replyTo, setReplyTo] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");

  useEffect(() => {
    let active = true;
    sendState(account, token)
      .then((s) => {
        if (!active) return;
        setEnabled(s.enabled);
        setBastionId(s.bastionId);
        setLoading(false);
      })
      .catch(() => active && setLoading(false));
    return () => {
      active = false;
    };
  }, [account, token]);

  async function enable(): Promise<void> {
    setBusy(true);
    setError(null);
    const r = await sendEnable(account, token).catch((e) => ({ error: (e as Error)?.message || "Could not enable Send." }));
    setBusy(false);
    if ("bastionId" in r) {
      setEnabled(true);
      setBastionId(r.bastionId);
    } else {
      setError(r.error);
    }
  }

  async function persist(next: Contact[]): Promise<void> {
    setContacts(next);
    await saveContacts(account, token, next).catch(() => toast("Saved locally — server sync failed"));
  }

  if (loading) {
    return (
      <>
        <div className="page-head"><h2>Bastion Send</h2></div>
        <div className="faint" style={{ padding: 20 }}>Loading…</div>
      </>
    );
  }

  const published = enabled && bastionId;

  // ── Enable / publish gate ──
  if (!published) {
    return (
      <>
        <div className="page-head"><h2>Bastion Send</h2></div>
        <div className="card-section send-enable">
          <div className="send-hero">
            <IcShared size={40} />
            <h3>End-to-end encrypted notes</h3>
            <p className="faint">
              Send encrypted notes to other Bastion users. Only your chosen recipient can open them —
              the server only ever stores ciphertext.
            </p>
          </div>
          <button className="btn btn-primary" disabled={busy} onClick={enable}>
            {busy ? "Working…" : enabled ? "Publish my address" : "Enable Send"}
          </button>
          {error && <div className="callout" style={{ marginTop: 12 }}>{error}</div>}
        </div>
      </>
    );
  }

  // ── Contacts ──
  if (view === "contacts") {
    return (
      <>
        <div className="page-head">
          <h2><button className="link-back" onClick={() => setView("home")}>Send</button> / Contacts</h2>
          <div className="right">
            <button className="btn btn-primary" onClick={() => { setError(null); setView("add"); }}>
              <IcPlus size={16} /> Add contact
            </button>
          </div>
        </div>
        <div className="card-section">
          {contacts.length === 0 ? (
            <div className="faint" style={{ padding: "8px 0" }}>No contacts yet. Add someone by their Bastion address.</div>
          ) : (
            contacts.map((c) => {
              const editing = editingId === c.bastion_id;
              const saveName = () => {
                const name = editName.trim() || c.bastion_id;
                persist(contacts.map((x) => (x.bastion_id === c.bastion_id ? { ...x, display: name } : x)));
                setEditingId(null);
              };
              return (
                <div className="contact-row" key={c.bastion_id}>
                  <div className="contact-meta">
                    {editing ? (
                      <input
                        className="input"
                        value={editName}
                        autoFocus
                        placeholder="Contact name"
                        onChange={(e) => setEditName(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") saveName();
                          if (e.key === "Escape") setEditingId(null);
                        }}
                      />
                    ) : (
                      <>
                        <div className="contact-name">{contactLabel(c)}</div>
                        <code
                          className="faint contact-addr"
                          title="Copy full address"
                          onClick={() => {
                            navigator.clipboard?.writeText(c.bastion_id);
                            toast("Bastion address copied");
                          }}
                        >
                          {shortId(c.bastion_id)}
                        </code>
                      </>
                    )}
                  </div>
                  <span className={`badge ${c.verified ? "badge-ok" : "badge-warn"}`}>{c.verified ? "Verified" : "Unverified"}</span>
                  {editing ? (
                    <button className="icon-btn icon-btn-ok" title="Save name" onClick={saveName}>✓</button>
                  ) : (
                    <button
                      className="icon-btn"
                      title="Rename"
                      onClick={() => {
                        setEditingId(c.bastion_id);
                        setEditName(c.display === c.bastion_id ? "" : c.display);
                      }}
                    >
                      <IcEdit size={16} />
                    </button>
                  )}
                  <button
                    className="icon-btn"
                    title="Remove"
                    onClick={() => persist(contacts.filter((x) => x.bastion_id !== c.bastion_id))}
                  >
                    <IcTrash size={16} />
                  </button>
                </div>
              );
            })
          )}
        </div>
      </>
    );
  }

  // ── Add contact (resolve) ──
  if (view === "add") {
    const find = async (raw: string): Promise<void> => {
      setBusy(true);
      setError(null);
      const r = await resolveContact(account, token, raw);
      setBusy(false);
      if ("error" in r) {
        setError(r.error);
      } else {
        setResolved(r);
        setView("verify");
      }
    };
    return <AddContact busy={busy} error={error} onBack={() => setView("contacts")} onFind={find} />;
  }

  // ── Inbox ──
  if (view === "inbox") {
    return <Inbox account={account} token={token} contacts={contacts} toast={toast} onBack={() => setView("home")} onReply={(id) => { setError(null); setReplyTo(id); setView("compose"); }} />;
  }

  // ── Compose ──
  if (view === "compose") {
    return (
      <Compose
        contacts={contacts}
        preselect={replyTo}
        onBack={() => setView("home")}
        onSend={async (recipientId, plaintext, opts) => {
          const c = contacts.find((x) => x.bastion_id === recipientId);
          if (!c) return { error: "Unknown recipient." };
          const r = await composeNote(account, token, c, plaintext, opts).catch((e) => ({
            error: (e as Error)?.message || "Send failed.",
          }));
          if ("ok" in r) {
            toast("Note sent");
            setView("home");
          }
          return r;
        }}
      />
    );
  }

  // ── Verify (safety number) ──
  if (view === "verify" && resolved) {
    const save = async (display: string, verified: boolean): Promise<void> => {
      const c: Contact = {
        bastion_id: resolved.bastionId,
        public: resolved.public,
        pinFp: resolved.pinFp,
        display: display.trim() || resolved.bastionId,
        verified,
        verified_at: verified ? Date.now() : null,
        safety_number: resolved.safety_number,
      };
      await persist([...contacts.filter((x) => x.bastion_id !== c.bastion_id), c]);
      toast(verified ? "Contact verified" : "Contact saved");
      setView("contacts");
    };
    return <VerifyContact resolved={resolved} onBack={() => setView("add")} onSave={save} />;
  }

  // ── Home ──
  return (
    <>
      <div className="page-head"><h2>Bastion Send</h2></div>
      <div className="card-section">
        <div className="field-label">Your Bastion address</div>
        <div className="id-card">
          <code>{bastionId}</code>
          <button
            className="icon-btn"
            title="Copy address"
            onClick={() => {
              navigator.clipboard?.writeText(bastionId!);
              toast("Bastion address copied");
            }}
          >
            <IcCopy size={16} />
          </button>
        </div>
        <p className="faint" style={{ margin: "10px 0 16px" }}>
          Share this address so other Bastion users can send you encrypted notes.
        </p>
        <div style={{ display: "flex", gap: 8 }}>
          <button className="btn btn-primary" onClick={() => { setError(null); setReplyTo(null); setView("compose"); }}>
            Compose note
          </button>
          <button className="btn" onClick={() => setView("inbox")}>Inbox</button>
          <button className="btn" onClick={() => setView("contacts")}>
            <IcShared size={16} /> Contacts {contacts.length > 0 && <span className="faint">{contacts.length}</span>}
          </button>
        </div>
      </div>
    </>
  );
}

function Compose({
  contacts,
  preselect,
  onBack,
  onSend,
}: {
  contacts: Contact[];
  preselect?: string | null;
  onBack: () => void;
  onSend: (
    recipientId: string,
    plaintext: string,
    opts: { passphrase?: string; signed: boolean; expiresAt?: number | null }
  ) => Promise<{ ok: true } | { error: string; keyChanged?: boolean }>;
}): JSX.Element {
  const [to, setTo] = useState(
    (preselect && contacts.some((c) => c.bastion_id === preselect) ? preselect : contacts[0]?.bastion_id) ?? ""
  );
  const [note, setNote] = useState("");
  const [signed, setSigned] = useState(true);
  const [pass, setPass] = useState("");
  const [exp, setExp] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (contacts.length === 0) {
    return (
      <>
        <div className="page-head"><h2><button className="link-back" onClick={onBack}>Send</button> / Compose</h2></div>
        <div className="card-section">
          <div className="faint">Add a contact first, then come back to send them a note.</div>
        </div>
      </>
    );
  }

  const submit = async (): Promise<void> => {
    if (!note.trim()) {
      setError("Write a note first.");
      return;
    }
    setBusy(true);
    setError(null);
    const expiresAt = exp !== "0" ? Math.floor(Date.now() / 1000) + Number(exp) : null;
    const r = await onSend(to, note, { passphrase: pass || undefined, signed, expiresAt });
    setBusy(false);
    if ("error" in r) setError(r.keyChanged ? "This contact's key changed — re-verify them before sending." : r.error);
  };

  return (
    <>
      <div className="page-head"><h2><button className="link-back" onClick={onBack}>Send</button> / Compose</h2></div>
      <div className="card-section">
        <div className="field-label">To</div>
        <select className="input" value={to} onChange={(e) => setTo(e.target.value)}>
          {contacts.map((c) => (
            <option key={c.bastion_id} value={c.bastion_id}>
              {contactLabel(c)} {c.verified ? "✓" : "(unverified)"}
            </option>
          ))}
        </select>

        <div className="field-label" style={{ marginTop: 14 }}>Note</div>
        <textarea
          className="textarea"
          rows={5}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          placeholder="Your encrypted note…"
          autoFocus
        />

        <label className="send-check">
          <input type="checkbox" checked={signed} onChange={(e) => setSigned(e.target.checked)} />
          Sign it (the recipient can verify it's from you)
        </label>

        <div className="field-label" style={{ marginTop: 14 }}>Extra passphrase (optional)</div>
        <input className="input" type="password" value={pass} onChange={(e) => setPass(e.target.value)} placeholder="shared out-of-band" />

        <div className="field-label" style={{ marginTop: 14 }}>Expires</div>
        <select className="input" value={exp} onChange={(e) => setExp(e.target.value)}>
          <option value="0">Never</option>
          <option value="3600">1 hour</option>
          <option value="86400">1 day</option>
          <option value="604800">7 days</option>
        </select>

        {error && <div className="callout" style={{ marginTop: 14 }}>{error}</div>}
        <button className="btn btn-primary" style={{ marginTop: 16 }} disabled={busy} onClick={submit}>
          {busy ? "Sending…" : "Send encrypted note"}
        </button>
      </div>
    </>
  );
}

function AddContact({
  busy,
  error,
  onBack,
  onFind,
}: {
  busy: boolean;
  error: string | null;
  onBack: () => void;
  onFind: (raw: string) => void;
}): JSX.Element {
  const [addr, setAddr] = useState("");
  return (
    <>
      <div className="page-head"><h2><button className="link-back" onClick={onBack}>Contacts</button> / Add</h2></div>
      <div className="card-section">
        <div className="field-label">Bastion address</div>
        <input
          className="input mono"
          value={addr}
          onChange={(e) => setAddr(e.target.value)}
          placeholder="NXKXR2TTCOKWPSMXORC7VWY5RI"
          autoFocus
          onKeyDown={(e) => e.key === "Enter" && onFind(addr)}
        />
        {error && <div className="callout" style={{ marginTop: 12 }}>{error}</div>}
        <button className="btn btn-primary" style={{ marginTop: 14 }} disabled={busy} onClick={() => onFind(addr)}>
          {busy ? "Finding…" : "Find"}
        </button>
      </div>
    </>
  );
}

function VerifyContact({
  resolved,
  onBack,
  onSave,
}: {
  resolved: Resolved;
  onBack: () => void;
  onSave: (display: string, verified: boolean) => void;
}): JSX.Element {
  const [name, setName] = useState("");
  const grouped = resolved.safety_number.replace(/(\d{5})(?=\d)/g, "$1 ");
  return (
    <>
      <div className="page-head"><h2><button className="link-back" onClick={onBack}>Add</button> / Verify</h2></div>
      <div className="card-section">
        <div className="field-label">Name (optional)</div>
        <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={resolved.bastionId} />
        <div className="field-label" style={{ marginTop: 16 }}>Safety number</div>
        <div className="safety-num">{grouped}</div>
        <p className="faint" style={{ lineHeight: 1.55 }}>
          Compare these 60 digits with the owner of <code>{resolved.bastionId}</code> over a separate,
          trusted channel (in person, a call). If they match, the connection is genuinely end-to-end —
          a malicious server can't impersonate them.
        </p>
        <button className="btn btn-primary" style={{ marginTop: 8 }} onClick={() => onSave(name, true)}>
          Numbers match — verify &amp; save
        </button>
        <button className="btn" style={{ marginTop: 8 }} onClick={() => onSave(name, false)}>
          Save without verifying
        </button>
      </div>
    </>
  );
}

// ── inbox ──
function senderName(o: Opened): string {
  if (o.sender?.state === "anonymous") return "Anonymous sender";
  return o.display || (o.sender?.id ? shortId(o.sender.id) : "Unknown sender");
}
function senderChip(o: Opened): JSX.Element {
  if (o.keyChanged) return <span className="badge badge-danger">Key changed</span>;
  const st = o.sender?.state;
  if (st === "verified") return <span className="badge badge-ok">Verified</span>;
  if (st === "anonymous") return <span className="badge">Anonymous</span>;
  return <span className="badge badge-warn">Unverified</span>;
}
function fmtTime(sec: number): string {
  if (!sec) return "";
  return new Date(sec * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

type Row = { item: InboxItem; opened: Opened };

function Inbox({
  account,
  token,
  contacts,
  toast,
  onBack,
  onReply,
}: {
  account: Account;
  token: string;
  contacts: Contact[];
  toast: (m: string) => void;
  onBack: () => void;
  onReply: (id: string) => void;
}): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rows, setRows] = useState<Row[]>([]);
  const [open, setOpen] = useState<Row | null>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    inboxList(token)
      .then((list) => {
        if (!active) return;
        setRows(list.map((item) => ({ item, opened: openMessage(account, contacts, item.blob, undefined) })));
        setLoading(false);
      })
      .catch((e) => {
        if (!active) return;
        setError((e as Error)?.message || "Could not load inbox.");
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [account, token, contacts]);

  if (open) {
    return (
      <Message
        account={account}
        contacts={contacts}
        row={open}
        onBack={() => setOpen(null)}
        onReply={onReply}
        onDelete={async () => {
          await inboxDelete(token, open.item.message_id).catch(() => {});
          setRows((r) => r.filter((x) => x.item.message_id !== open.item.message_id));
          setOpen(null);
          toast("Message deleted");
        }}
      />
    );
  }

  return (
    <>
      <div className="page-head"><h2><button className="link-back" onClick={onBack}>Send</button> / Inbox</h2></div>
      <div className="card-section">
        {loading ? (
          <div className="faint">Loading…</div>
        ) : error ? (
          <div className="callout">{error}</div>
        ) : rows.length === 0 ? (
          <div className="faint">No messages.</div>
        ) : (
          rows.map((r) => (
            <div className="msg-row" key={r.item.message_id} onClick={() => setOpen(r)}>
              <div className="msg-meta">
                <div className="msg-from">{senderName(r.opened)}</div>
                <div className="faint msg-prev">{r.opened.needsPass ? "🔒 Passphrase required" : (r.opened.plaintext || "").slice(0, 70)}</div>
              </div>
              <div className="msg-right">{senderChip(r.opened)}<div className="faint msg-time">{fmtTime(r.item.created_at)}</div></div>
            </div>
          ))
        )}
      </div>
    </>
  );
}

function Message({
  account,
  contacts,
  row,
  onBack,
  onReply,
  onDelete,
}: {
  account: Account;
  contacts: Contact[];
  row: Row;
  onBack: () => void;
  onReply: (id: string) => void;
  onDelete: () => void;
}): JSX.Element {
  const [data, setData] = useState<Opened>(row.opened);
  const [pass, setPass] = useState("");
  const [error, setError] = useState<string | null>(null);

  const banner = data.keyChanged ? (
    <div className="trust trust-danger">This contact's key changed since you verified them. Don't trust this message — re-verify them.</div>
  ) : data.sender?.state === "verified" ? (
    <div className="trust trust-ok">Verified — from {data.display || shortId(data.sender.id!)}</div>
  ) : data.sender?.state === "anonymous" ? (
    <div className="trust">Anonymous sender — Bastion can't tell you who sent this.</div>
  ) : (
    <div className="trust trust-warn">Unverified sender{data.sender?.id ? ` · ${shortId(data.sender.id)}` : ""}. Add &amp; verify them to confirm their identity.</div>
  );

  return (
    <>
      <div className="page-head">
        <h2><button className="link-back" onClick={onBack}>Inbox</button> / Message</h2>
        <div className="right"><button className="btn" onClick={onDelete}><IcTrash size={16} /> Delete</button></div>
      </div>
      <div className="card-section">
        {data.needsPass ? (
          <>
            <div className="trust">🔒 This note is protected by an extra passphrase.</div>
            <div className="field-label" style={{ marginTop: 12 }}>Passphrase</div>
            <input
              className="input"
              type="password"
              value={pass}
              autoFocus
              onChange={(e) => setPass(e.target.value)}
              onKeyDown={(e) => {
                if (e.key !== "Enter") return;
                const o = openMessage(account, contacts, row.item.blob, pass);
                if (o.error) setError(o.error);
                else { setData(o); setError(null); }
              }}
            />
            {error && <div className="callout" style={{ marginTop: 12 }}>{error}</div>}
            <button
              className="btn btn-primary"
              style={{ marginTop: 14 }}
              onClick={() => {
                const o = openMessage(account, contacts, row.item.blob, pass);
                if (o.error) setError(o.error);
                else { setData(o); setError(null); }
              }}
            >
              Open
            </button>
          </>
        ) : (
          <>
            {banner}
            <div className="note-body">{data.plaintext}</div>
            {data.sender?.id && (
              <button className="btn" style={{ marginTop: 14 }} onClick={() => onReply(data.sender!.id!)}>Reply</button>
            )}
          </>
        )}
      </div>
    </>
  );
}
