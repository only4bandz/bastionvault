import { useEffect, useState, type JSX } from "react";
import type { ItemType, VaultItem } from "../lib/types";
import { generatePassword } from "../lib/generator";
import { detectScheme, lookupBin } from "../lib/bin";
import { IcCard, IcKey, IcNote, IcRefresh, IcX } from "./icons";

const NEW = (): VaultItem => ({
  id: crypto.randomUUID(),
  type: "login",
  title: "",
  updatedAt: Date.now(),
});

export function ItemEditor({
  initial,
  onSave,
  onClose,
}: {
  initial: VaultItem | null;
  onSave: (item: VaultItem) => void;
  onClose: () => void;
}): JSX.Element {
  const [item, setItem] = useState<VaultItem>(initial ?? NEW());
  const set = <K extends keyof VaultItem>(k: K, v: VaultItem[K]) => setItem((p) => ({ ...p, [k]: v }));

  // Detect the card network locally (instant) and the issuing bank from the BIN
  // (debounced lookup), so the item shows the right logo.
  useEffect(() => {
    if (item.type !== "card") return;
    const num = item.cardNumber || "";
    const scheme = detectScheme(num);
    setItem((p) => {
      const next = scheme === "unknown" ? undefined : scheme;
      return p.cardBrand === next ? p : { ...p, cardBrand: next };
    });
    const bin = num.replace(/\D/g, "").slice(0, 8);
    if (bin.length < 6) return;
    const t = setTimeout(() => {
      lookupBin(bin).then((r) => {
        if (r && (r.bankDomain || r.bankName)) {
          setItem((p) => ({ ...p, cardBank: r.bankName, cardBankDomain: r.bankDomain }));
        }
      });
    }, 400);
    return () => clearTimeout(t);
  }, [item.cardNumber, item.type]);

  function save() {
    if (!item.title.trim()) return;
    onSave({ ...item, updatedAt: Date.now() });
  }

  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <h3>{initial ? "Edit item" : "New item"}</h3>
          <button className="icon-btn x" onClick={onClose}><IcX size={18} /></button>
        </div>
        <div className="modal-body">
          {!initial && (
            <div className="type-pick">
              {([
                ["login", "Login", <IcKey size={18} key="k" />],
                ["note", "Note", <IcNote size={18} key="n" />],
                ["card", "Card", <IcCard size={18} key="c" />],
              ] as [ItemType, string, JSX.Element][]).map(([t, label, ic]) => (
                <button key={t} className={item.type === t ? "active" : ""} onClick={() => set("type", t)}>
                  {ic}
                  {label}
                </button>
              ))}
            </div>
          )}

          <div className="field">
            <label>Name</label>
            <input className="input" autoFocus value={item.title} onChange={(e) => set("title", e.target.value)} placeholder="e.g. GitHub" />
          </div>

          {item.type === "login" && (
            <>
              <div className="field">
                <label>Username / email</label>
                <input className="input" value={item.username ?? ""} onChange={(e) => set("username", e.target.value)} />
              </div>
              <div className="field">
                <label>Password</label>
                <div className="input-row">
                  <input className="input mono" value={item.password ?? ""} onChange={(e) => set("password", e.target.value)} />
                  <button className="btn" title="Generate" onClick={() => set("password", generatePassword({ length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true }))}>
                    <IcRefresh size={16} />
                  </button>
                </div>
              </div>
              <div className="field">
                <label>Website</label>
                <input className="input" value={item.url ?? ""} onChange={(e) => set("url", e.target.value)} placeholder="https://" />
              </div>
            </>
          )}

          {item.type === "card" && (
            <>
              <div className="field">
                <label>Card number</label>
                <input className="input mono" value={item.cardNumber ?? ""} onChange={(e) => set("cardNumber", e.target.value)} placeholder="•••• •••• •••• ••••" />
                {(item.cardBank || item.cardBrand) && (
                  <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
                    Detected: {item.cardBank ? `${item.cardBank} · ` : ""}
                    {(item.cardBrand || "").toUpperCase()}
                  </div>
                )}
              </div>
              <div className="input-row">
                <div className="field" style={{ flex: 1 }}>
                  <label>Expiry</label>
                  <input className="input mono" placeholder="MM/YY" value={item.cardExp ?? ""} onChange={(e) => set("cardExp", e.target.value)} />
                </div>
                <div className="field" style={{ flex: 1 }}>
                  <label>CVV</label>
                  <input className="input mono" value={item.cardCvv ?? ""} onChange={(e) => set("cardCvv", e.target.value)} />
                </div>
              </div>
            </>
          )}

          <div className="field">
            <label>Notes</label>
            <textarea className="textarea" value={item.notes ?? ""} onChange={(e) => set("notes", e.target.value)} />
          </div>
        </div>
        <div className="modal-foot">
          <span className="spacer" />
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={save} disabled={!item.title.trim()}>Save</button>
        </div>
      </div>
    </div>
  );
}
