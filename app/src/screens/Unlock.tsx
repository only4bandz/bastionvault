import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { IcLock } from "../components/icons";
import { ensureWasm, unlock, type Account } from "../lib/wasm";

export function Unlock({
  registrationJson,
  onUnlocked,
}: {
  registrationJson: string;
  onUnlocked: (a: Account) => void;
}): JSX.Element {
  const [pw, setPw] = useState("");
  const [sk, setSk] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function doUnlock() {
    setErr("");
    setBusy(true);
    await new Promise((r) => setTimeout(r, 30));
    try {
      await ensureWasm();
      const account = unlock(pw, sk, registrationJson);
      onUnlocked(account);
    } catch {
      setErr("Invalid master password or Secret Key.");
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card">
        <Brand />
        <h1>
          <IcLock size={20} /> Vault locked
        </h1>
        <p className="sub">Enter your master password and Secret Key to unlock.</p>

        <div className="field">
          <label>Master password</label>
          <input
            className="input"
            type="password"
            autoFocus
            value={pw}
            onChange={(e) => setPw(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Secret Key</label>
          <input
            className="input mono"
            value={sk}
            placeholder="A1-XXXXX-XXXXX-…"
            onChange={(e) => setSk(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doUnlock()}
          />
        </div>

        {err && <div className="callout">{err}</div>}

        <button className="btn btn-primary btn-block" onClick={doUnlock} disabled={busy}>
          {busy ? "Unlocking…" : "Unlock"}
        </button>
      </div>
    </div>
  );
}
