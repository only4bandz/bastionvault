import { useEffect, useState, type JSX } from "react";
import type { Account } from "../lib/wasm";
import { sendState, sendEnable } from "../lib/send";
import { IcCopy, IcShared } from "../components/icons";

/** Bastion Send — web app surface. Slice 1: enable + your Bastion address. */
export function Send({
  account,
  token,
  toast,
}: {
  account: Account;
  token: string;
  toast: (m: string) => void;
}): JSX.Element {
  const [loading, setLoading] = useState(true);
  const [enabled, setEnabled] = useState(false);
  const [bastionId, setBastionId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

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

  if (loading) {
    return (
      <>
        <div className="page-head"><h2>Bastion Send</h2></div>
        <div className="faint" style={{ padding: 20 }}>Loading…</div>
      </>
    );
  }

  const published = enabled && bastionId;

  return (
    <>
      <div className="page-head"><h2>Bastion Send</h2></div>
      {!published ? (
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
      ) : (
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
          <p className="faint" style={{ marginTop: 10 }}>
            Share this address so other Bastion users can send you encrypted notes.
          </p>
        </div>
      )}
    </>
  );
}
