import { useEffect, useState, type JSX } from "react";
import type { Account } from "../lib/wasm";
import {
  sendState,
  sendEnable,
  saveContacts,
  resolveContact,
  type Contact,
  type Resolved,
} from "../lib/send";
import { IcCopy, IcShared, IcPlus, IcTrash } from "../components/icons";

type View = "home" | "contacts" | "add" | "verify";

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
          <button className="btn btn-primary" onClick={() => { setError(null); setView("add"); }}>
            <IcPlus size={16} /> Add contact
          </button>
        </div>
        <div className="card-section">
          {contacts.length === 0 ? (
            <div className="faint" style={{ padding: "8px 0" }}>No contacts yet. Add someone by their Bastion address.</div>
          ) : (
            contacts.map((c) => (
              <div className="contact-row" key={c.bastion_id}>
                <div className="contact-meta">
                  <div className="contact-name">{c.display}</div>
                  <code className="faint">{c.bastion_id}</code>
                </div>
                <span className={`badge ${c.verified ? "badge-ok" : "badge-warn"}`}>{c.verified ? "Verified" : "Unverified"}</span>
                <button
                  className="icon-btn"
                  title="Remove"
                  onClick={() => persist(contacts.filter((x) => x.bastion_id !== c.bastion_id))}
                >
                  <IcTrash size={16} />
                </button>
              </div>
            ))
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
        <button className="btn" onClick={() => setView("contacts")}>
          <IcShared size={16} /> Contacts {contacts.length > 0 && <span className="faint">{contacts.length}</span>}
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
