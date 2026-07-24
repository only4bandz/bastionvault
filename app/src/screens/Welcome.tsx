import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { SecretInput } from "../components/SecretInput";
import { assessPassword } from "../lib/password-health";
import { checkPwnedPassword } from "../lib/pwned-passwords";

export function Welcome({
  onCreate,
  onHaveVault,
  verificationRequired,
  verifiedEmail,
  onRequestVerification,
}: {
  onCreate: (email: string, password: string) => Promise<void>;
  onHaveVault: () => void;
  verificationRequired: boolean | null;
  verifiedEmail: string | null;
  onRequestVerification: (email: string) => Promise<void>;
}): JSX.Element {
  const [email, setEmail] = useState(verifiedEmail ?? "");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [breachCheck, setBreachCheck] = useState(false);
  const s = assessPassword(pw);

  async function create() {
    setErr("");
    if (!/^\S+@\S+\.\S+$/.test(email)) return setErr("Enter a valid email address.");
    if (verificationRequired === null) {
      return setErr("Server registration policy is unavailable. Try again.");
    }
    if (verificationRequired && !verifiedEmail) {
      setBusy(true);
      try {
        await onRequestVerification(email);
      } catch (e) {
        setErr(e instanceof Error ? e.message : "Could not send the verification email.");
        setBusy(false);
      }
      return;
    }
    if (pw.length < 8) return setErr("Use at least 8 characters for your master password.");
    // The master password protects everything and cannot be reset — refuse an
    // obviously weak one (common word, sequence, single class, too short) that
    // the offline strength check flags. score < 2 = "Very weak"/"Weak".
    if (s.score < 2) {
      return setErr(`This master password is too weak (${s.reasons[0].toLowerCase()}). Try a longer passphrase.`);
    }
    if (pw !== pw2) return setErr("Passwords do not match.");
    if (breachCheck) {
      setBusy(true);
      let occurrences: number;
      try {
        occurrences = await checkPwnedPassword(pw);
      } catch {
        setBusy(false);
        return setErr(
          "The breach check could not reach haveibeenpwned.com. Retry, or untick the check to continue without it."
        );
      }
      if (occurrences > 0) {
        setBusy(false);
        return setErr(
          `This password appears in ${occurrences.toLocaleString()} known breaches. It will be attacked first — choose a different one.`
        );
      }
      setBusy(false);
    }
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
              value={verifiedEmail ?? email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              readOnly={Boolean(verifiedEmail)}
            />
            <small>
              {verifiedEmail
                ? "Mailbox verified for registration only — never for vault recovery."
                : verificationRequired
                  ? "We verify mailbox control before creating an account."
                  : "Used as a local development login identifier, not for recovery."}
            </small>
          </div>
          {(verificationRequired === false || verifiedEmail) && (
            <>
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
                  <div
                    className="strength strength-steps"
                    title={s.label}
                    role="meter"
                    aria-label="Master password strength"
                    aria-valuemin={0}
                    aria-valuemax={4}
                    aria-valuenow={s.score}
                    aria-valuetext={s.label}
                  >
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
              <label className="send-check" style={{ marginTop: 0, marginBottom: 14 }}>
                <input
                  type="checkbox"
                  checked={breachCheck}
                  onChange={(event) => setBreachCheck(event.target.checked)}
                />
                <span>
                  Check this password against known breaches. Only a 5-character
                  hash prefix is sent to haveibeenpwned.com — never the password.
                </span>
              </label>
            </>
          )}

          {err && <div className="callout callout-danger" role="alert">{err}</div>}

          <button
            className="btn btn-primary btn-block"
            type="submit"
            disabled={busy || verificationRequired === null}
          >
            {busy
              ? verificationRequired && !verifiedEmail
                ? "Sending verification…"
                : "Creating your vault…"
              : verificationRequired === null
                ? "Checking server policy…"
                : verificationRequired && !verifiedEmail
                ? "Verify email first"
                : "Create vault"}
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
