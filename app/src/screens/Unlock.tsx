import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { SecretInput } from "../components/SecretInput";
import { IcLock } from "../components/icons";

export function Unlock({
  onUnlock,
  onCreateNew,
}: {
  onUnlock: (email: string, password: string, secretKey: string) => Promise<void>;
  onCreateNew: () => void;
}): JSX.Element {
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [sk, setSk] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function go() {
    setErr("");
    if (!email || !pw || !sk) return setErr("Email, master password and Secret Key are all required.");
    setBusy(true);
    await new Promise((r) => setTimeout(r, 30));
    try {
      await onUnlock(email, pw, sk);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Could not unlock.");
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card">
        <Brand />
        <h1>
          <IcLock size={20} /> Unlock your vault
        </h1>
        <p className="sub">
          Enter your email, master password and Secret Key. We fetch your
          encrypted vault from the server and decrypt it here, on your device.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void go();
          }}
        >
          <div className="field">
            <label>Email</label>
            <input className="input" type="email" autoComplete="email" autoFocus value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
            <small>This server does not verify mailbox ownership or provide email recovery.</small>
          </div>
          <div className="field">
            <label>Master password</label>
            <SecretInput label="Master password" autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
          </div>
          <div className="field">
            <label>Secret Key</label>
            <input
              className="input mono"
              value={sk}
              placeholder="A1-XXXXX-XXXXX-…"
              autoComplete="off"
              onChange={(e) => setSk(e.target.value)}
            />
          </div>

          {err && <div className="callout">{err}</div>}

          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            {busy ? "Unlocking…" : "Unlock"}
          </button>
        </form>

        <div className="auth-foot">
          New here?{" "}
          <button className="link-btn" onClick={onCreateNew}>
            Create a vault
          </button>
        </div>
      </div>
    </div>
  );
}
