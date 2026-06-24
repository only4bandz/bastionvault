import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { ensureWasm, register, type Account } from "../lib/wasm";
import { strength } from "../lib/generator";

export function Welcome({
  onCreated,
  onHaveVault,
}: {
  onCreated: (a: Account) => void;
  onHaveVault: () => void;
}): JSX.Element {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const s = strength(pw);

  async function create() {
    setErr("");
    if (pw.length < 8) {
      setErr("Use at least 8 characters for your master password.");
      return;
    }
    if (pw !== pw2) {
      setErr("Passwords do not match.");
      return;
    }
    setBusy(true);
    // Yield so the "Creating…" state paints before Argon2id blocks the thread.
    await new Promise((r) => setTimeout(r, 30));
    try {
      await ensureWasm();
      const account = register(pw);
      onCreated(account);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card">
        <Brand />
        <h1>Create your vault</h1>
        <p className="sub">
          Your master password never leaves this device. We derive your keys
          locally and pair them with a one-time <b>Secret Key</b> — so even we
          could never read your vault.
        </p>

        <div className="field">
          <label>Master password</label>
          <input
            className="input"
            type="password"
            autoFocus
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            placeholder="A long, memorable passphrase"
            onKeyDown={(e) => e.key === "Enter" && document.getElementById("pw2")?.focus()}
          />
          {pw && (
            <div className="strength" title={s.label}>
              <i style={{ width: `${(s.score / 4) * 100}%`, background: s.color }} />
            </div>
          )}
        </div>

        <div className="field">
          <label>Confirm master password</label>
          <input
            id="pw2"
            className="input"
            type="password"
            value={pw2}
            onChange={(e) => setPw2(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && create()}
            placeholder="Repeat it"
          />
        </div>

        {err && <div className="callout">{err}</div>}

        <button className="btn btn-primary btn-block" onClick={create} disabled={busy}>
          {busy ? "Creating your vault…" : "Create vault"}
        </button>

        <div className="auth-foot">
          Already locked out?{" "}
          <button className="link-btn" onClick={onHaveVault}>
            Unlock an existing vault
          </button>
        </div>
      </div>
    </div>
  );
}
