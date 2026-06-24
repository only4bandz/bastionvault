import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { strength } from "../lib/generator";

export function Welcome({
  onCreate,
  onHaveVault,
}: {
  onCreate: (email: string, password: string) => Promise<void>;
  onHaveVault: () => void;
}): JSX.Element {
  const [email, setEmail] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const s = strength(pw);

  async function create() {
    setErr("");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setErr("Enter a valid email address.");
    if (pw.length < 8) return setErr("Use at least 8 characters for your master password.");
    if (pw !== pw2) return setErr("Passwords do not match.");
    setBusy(true);
    await new Promise((r) => setTimeout(r, 30)); // let "Creating…" paint before Argon2id blocks
    try {
      await onCreate(email, pw);
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
          <label>Email</label>
          <input
            className="input"
            type="email"
            autoFocus
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
          />
        </div>
        <div className="field">
          <label>Master password</label>
          <input
            className="input"
            type="password"
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            placeholder="A long, memorable passphrase"
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
          Already have a vault?{" "}
          <button className="link-btn" onClick={onHaveVault}>
            Unlock an existing vault
          </button>
        </div>
      </div>
    </div>
  );
}
