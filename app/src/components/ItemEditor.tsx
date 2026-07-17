import { useEffect, useRef, useState, type JSX } from "react";
import type { ItemType, VaultItem } from "../lib/types";
import { generatePassword } from "../lib/generator";
import { detectScheme, lookupBin } from "../lib/bin";
import { IcCard, IcKey, IcNote, IcRefresh } from "./icons";
import { ConfirmDialog } from "./ConfirmDialog";
import { Dialog } from "./Dialog";
import { SecretInput } from "./SecretInput";

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
  onSave: (item: VaultItem) => Promise<boolean>;
  onClose: () => void;
}): JSX.Element {
  const [item, setItem] = useState<VaultItem>(initial ?? NEW());
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [confirmingDiscard, setConfirmingDiscard] = useState(false);
  const titleRef = useRef<HTMLInputElement>(null);
  const set = <K extends keyof VaultItem>(k: K, v: VaultItem[K]) => {
    setDirty(true);
    setItem((p) => ({ ...p, [k]: v }));
  };

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
        if (r && (r.bankDomain || r.bankName || r.cardType)) {
          setItem((p) => ({
            ...p,
            cardBank: r.bankName ?? p.cardBank,
            cardBankDomain: r.bankDomain ?? p.cardBankDomain,
            cardType: r.cardType ?? p.cardType,
          }));
        }
      });
    }, 400);
    return () => clearTimeout(t);
  }, [item.cardNumber, item.type]);

  async function save() {
    if (!item.title.trim()) return;
    setSaving(true);
    const now = Date.now();
    // Track password age separately: any edit bumps updatedAt, but only an
    // actual password change resets the age clock used by Password Health.
    const passwordChangedAt =
      item.password && item.password !== initial?.password
        ? now
        : item.passwordChangedAt ?? initial?.passwordChangedAt;
    const saved = await onSave({
      ...item,
      updatedAt: now,
      ...(passwordChangedAt !== undefined ? { passwordChangedAt } : {}),
    });
    if (!saved) setSaving(false);
  }

  function requestClose(): void {
    if (saving) return;
    if (dirty) setConfirmingDiscard(true);
    else onClose();
  }

  return (
    <>
      <Dialog
        title={initial ? "Edit item" : "New item"}
        onClose={requestClose}
        closeDisabled={saving}
        inactive={confirmingDiscard}
        initialFocusRef={titleRef}
        footer={
          <>
            <span className="spacer" />
            <button className="btn btn-ghost" onClick={requestClose} disabled={saving}>Cancel</button>
            <button
              className="btn btn-primary"
              onClick={() => void save()}
              disabled={!item.title.trim() || saving}
            >
              {saving ? "Saving…" : "Save"}
            </button>
          </>
        }
      >
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
            <label htmlFor="item-title">Name</label>
            <input id="item-title" ref={titleRef} className="input" autoComplete="off" value={item.title} onChange={(e) => set("title", e.target.value)} placeholder="e.g. GitHub" />
          </div>

          {item.type === "login" && (
            <>
              <div className="field">
                <label htmlFor="item-username">Username / email</label>
                <input id="item-username" className="input" autoComplete="off" autoCapitalize="none" spellCheck={false} value={item.username ?? ""} onChange={(e) => set("username", e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="item-password">Password</label>
                <div className="input-row">
                  <SecretInput
                    key="login-password"
                    id="item-password"
                    label="Password"
                    className="mono"
                    autoComplete="new-password"
                    autoCapitalize="none"
                    spellCheck={false}
                    value={item.password ?? ""}
                    onChange={(e) => set("password", e.target.value)}
                  />
                  <button className="btn" aria-label="Generate password" onClick={() => set("password", generatePassword({ length: 20, lower: true, upper: true, digits: true, symbols: true, avoidAmbiguous: true }))}>
                    <IcRefresh size={16} />
                  </button>
                </div>
              </div>
              <div className="field">
                <label htmlFor="item-url">Website</label>
                <input id="item-url" className="input" type="url" autoComplete="off" autoCapitalize="none" spellCheck={false} value={item.url ?? ""} onChange={(e) => set("url", e.target.value)} placeholder="https://" />
              </div>
            </>
          )}

          {item.type === "card" && (
            <>
              <div className="field">
                <label htmlFor="item-cardholder">Cardholder name</label>
                <input
                  id="item-cardholder"
                  className="input"
                  autoComplete="cc-name"
                  value={item.cardholderName ?? ""}
                  onChange={(e) => set("cardholderName", e.target.value)}
                />
              </div>
              <div className="field">
                <label htmlFor="item-card-number">Card number</label>
                <SecretInput
                  key="card-number"
                  id="item-card-number"
                  label="Card number"
                  className="mono"
                  autoComplete="cc-number"
                  inputMode="numeric"
                  maxLength={23}
                  value={item.cardNumber ?? ""}
                  onChange={(e) => set("cardNumber", e.target.value)}
                  placeholder="•••• •••• •••• ••••"
                />
                {(item.cardBank || item.cardBrand || item.cardType) && (
                  <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
                    Detected: {item.cardBank ? `${item.cardBank} · ` : ""}
                    {(item.cardBrand || "").toUpperCase()}
                    {item.cardType ? ` · ${item.cardType}` : ""}
                  </div>
                )}
              </div>
              <div className="input-row">
                <div className="field" style={{ flex: 1 }}>
                  <label htmlFor="item-card-expiry">Expiry</label>
                  <input id="item-card-expiry" className="input mono" autoComplete="cc-exp" inputMode="numeric" maxLength={5} placeholder="MM/YY" value={item.cardExp ?? ""} onChange={(e) => set("cardExp", e.target.value)} />
                </div>
                <div className="field" style={{ flex: 1 }}>
                  <label htmlFor="item-card-cvv">CVV</label>
                  <SecretInput
                    key="card-cvv"
                    id="item-card-cvv"
                    label="CVV"
                    className="mono"
                    autoComplete="cc-csc"
                    inputMode="numeric"
                    maxLength={4}
                    value={item.cardCvv ?? ""}
                    onChange={(e) => set("cardCvv", e.target.value)}
                  />
                </div>
              </div>
            </>
          )}

          <div className="field">
            <label htmlFor="item-notes">Notes</label>
            <textarea id="item-notes" className="textarea" value={item.notes ?? ""} onChange={(e) => set("notes", e.target.value)} />
          </div>
      </Dialog>
      {confirmingDiscard && (
        <ConfirmDialog
          title="Discard unsaved changes?"
          confirmLabel="Discard changes"
          onClose={() => setConfirmingDiscard(false)}
          onConfirm={async () => {
            onClose();
            return true;
          }}
        >
          Your edits have not been saved. Discarding them cannot be undone.
        </ConfirmDialog>
      )}
    </>
  );
}
