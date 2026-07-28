import { useEffect, useRef, useState, type JSX } from "react";
import { Brand } from "../components/Brand";
import { IcCopy } from "../components/icons";
import {
  clearPendingSecretCopy,
  copySecretWithFeedback,
  SECRET_KEY_CLEAR_MS,
} from "../lib/clipboard";
import type { Account, RevealedSecret } from "../lib/wasm";

export function RevealSecret({
  account,
  onDone,
  toast,
}: {
  account: Account;
  onDone: () => Promise<void>;
  toast: (m: string) => void;
}): JSX.Element {
  const done = useRef(false);
  const [data, setData] = useState<RevealedSecret | null>(null);
  const [err, setErr] = useState("");
  const [saved, setSaved] = useState(false);
  const [showKit, setShowKit] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [submitErr, setSubmitErr] = useState("");

  // `reveal_secret` is one-shot (it consumes the Secret Key). Guard against
  // React StrictMode's double-invoke so we only call it once.
  useEffect(() => {
    if (done.current) return;
    done.current = true;
    try {
      const json = account.reveal_secret("Bastion vault");
      setData(JSON.parse(json) as RevealedSecret);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    }
  }, [account]);

  // The printable Emergency Kit (master-password hints aside, it contains the
  // full Secret Key) auto-collapses when the tab is hidden, mirroring the item
  // detail view's conceal-on-hide: a backgrounded tab must not keep the kit
  // on screen for whoever looks next. The user reopens it with one click.
  // Losing window focus collapses it too, for the same reason the item detail
  // view conceals there: the kit stays readable to anything pointed at this
  // window while the user is looking at another one.
  useEffect(() => {
    const onVisibilityChange = (): void => {
      if (document.visibilityState === "hidden") setShowKit(false);
    };
    const onWindowBlur = (): void => setShowKit(false);
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("blur", onWindowBlur);
    window.addEventListener("pagehide", onWindowBlur);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("blur", onWindowBlur);
      window.removeEventListener("pagehide", onWindowBlur);
    };
  }, []);

  function copy() {
    // Scheduled wipe: the Secret Key must never sit on the OS clipboard
    // indefinitely (it used to outlive vault creation, lock, and the session).
    if (data) {
      void copySecretWithFeedback(data.secret_key, "Secret Key", toast, undefined, SECRET_KEY_CLEAR_MS);
    }
  }

  async function finish() {
    setSubmitErr("");
    setSubmitting(true);
    // The user has confirmed the key is saved; a still-pending clipboard copy
    // must not follow them into the unlocked session.
    await clearPendingSecretCopy();
    try {
      await onDone();
    } catch (e) {
      setSubmitErr(e instanceof Error ? e.message : "Could not create the vault.");
      setSubmitting(false);
    }
  }

  return (
    <div className="auth">
      <div className="auth-card">
        <Brand />
        <h1>Save your Secret Key</h1>
        <p className="sub">
          This is the second half of your encryption — shown <b>only once</b>.
          Combined with your master password it makes your vault uncrackable.
          Store it somewhere safe. We can never recover it for you.
        </p>

        {err && <div className="callout callout-danger" role="alert">Could not display the Secret Key: {err}</div>}

        {data && (
          <>
            <div className="field">
              <label>Secret Key</label>
              <div className="secret-box mono">{data.secret_key}</div>
            </div>
            <button className="btn btn-block" onClick={copy}>
              <IcCopy size={16} /> Copy Secret Key
            </button>

            <button
              className="link-btn"
              style={{ display: "block", margin: "14px auto 0" }}
              onClick={() => setShowKit((v) => !v)}
            >
              {showKit ? "Hide" : "Show"} printable Emergency Kit
            </button>
            {showKit && <pre className="kit-pre mono">{data.emergency_kit}</pre>}

            <label
              style={{ display: "flex", gap: 10, alignItems: "center", margin: "20px 0", fontSize: 14, color: "var(--text-dim)" }}
            >
              <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
              I have saved my Secret Key somewhere safe.
            </label>

            {submitErr && <div className="callout callout-danger" role="alert">{submitErr}</div>}

            <button
              className="btn btn-primary btn-block"
              disabled={!saved || submitting}
              onClick={() => void finish()}
            >
              {submitting ? <><span className="spinner" aria-hidden="true" /> Creating your vault…</> : "Create and enter my vault"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}
