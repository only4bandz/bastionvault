import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { SecretInput } from "../components/SecretInput";
import { assessPassword } from "../lib/password-health";

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
  const s = assessPassword(pw);

  async function create() {
    setErr("");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setErr("Enter a valid email address.");
    if (pw.length < 8) return setErr("Use at least 8 characters for your master password.");
    // The master password protects everything and cannot be reset — refuse an
    // obviously weak one (common word, sequence, single class, too short) that
    // the offline strength check flags. score < 2 = "Very weak"/"Weak".
    if (s.score < 2) {
      return setErr(`This master password is too weak (${s.reasons[0].toLowerCase()}). Try a longer passphrase.`);
    }
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

        <form
          onSubmit={(e) => {
            e.preventDefault();
            void create();
          }}
        >
          <div className="field">
            <label>Email</label>
            <input
              className="input"
              type="email"
              autoComplete="email"
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
            />
            <small>Used as an unverified login identifier, not for recovery.</small>
          </div>
          <div className="field">
            <label>Master password</label>
            <SecretInput
              label="Master password"
              autoComplete="new-password"
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
            <SecretInput
              label="Master password confirmation"
              autoComplete="new-password"
              value={pw2}
              onChange={(e) => setPw2(e.target.value)}
              placeholder="Repeat it"
            />
          </div>

          {err && <div className="callout">{err}</div>}

          <button className="btn btn-primary btn-block" type="submit" disabled={busy}>
            {busy ? "Creating your vault…" : "Create vault"}
          </button>
        </form>

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
