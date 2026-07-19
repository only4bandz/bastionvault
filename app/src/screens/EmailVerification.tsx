import { useState, type JSX } from "react";
import { Brand } from "../components/Brand";

export function EmailVerification({
  email,
  error,
  onResend,
  onBack,
}: {
  email: string;
  error: string | null;
  onResend: (email: string) => Promise<void>;
  onBack: () => void;
}): JSX.Element {
  const [address, setAddress] = useState(email);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");

  async function resend() {
    setMessage("");
    if (!/^\S+@\S+\.\S+$/.test(address)) {
      setMessage("Enter the mailbox used for registration.");
      return;
    }
    setBusy(true);
    try {
      await onResend(address);
      setMessage("If this address can register, a new link has been queued. Check your inbox.");
    } catch {
      setMessage("The server could not queue another verification email. Try again later.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card">
        <Brand />
        <h1>Verify your mailbox</h1>
        <p className="sub">
          Open the link sent to {email ? <b>{email}</b> : "your mailbox"}. The link expires after
          30 minutes. Verification proves mailbox control only; it can never reset or recover your
          vault.
        </p>

        {error && <div className="callout">{error}</div>}

        <div className="field">
          <label>Email</label>
          <input
            className="input"
            type="email"
            autoComplete="email"
            value={address}
            onChange={(event) => setAddress(event.target.value)}
            placeholder="you@example.com"
          />
        </div>
        {message && <div className="callout">{message}</div>}
        <button className="btn btn-primary btn-block" onClick={() => void resend()} disabled={busy}>
          {busy ? "Queueing…" : "Send a new link"}
        </button>
        <div className="auth-foot">
          <button className="link-btn" onClick={onBack}>Back</button>
        </div>
      </div>
    </div>
  );
}
