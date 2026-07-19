import { useEffect, useMemo, useRef, useState, type JSX } from "react";
import { Favicon } from "../components/Favicon";
import { scanPwnedPasswords, type PwnedPasswordFinding } from "../lib/pwned-passwords";
import type { VaultItem } from "../lib/types";

type ScanState = "idle" | "running" | "done" | "error";

export function BreachScanner({
  items,
  onOpen,
}: {
  items: VaultItem[];
  onOpen: (item: VaultItem) => void;
}): JSX.Element {
  const [consented, setConsented] = useState(false);
  const [state, setState] = useState<ScanState>("idle");
  const [findings, setFindings] = useState<PwnedPasswordFinding[]>([]);
  const [error, setError] = useState("");
  const controller = useRef<AbortController | null>(null);
  const eligible = useMemo(
    () => items.filter((item) => item.type === "login" && Boolean(item.password)),
    [items]
  );

  useEffect(() => () => controller.current?.abort(), []);

  async function scan(): Promise<void> {
    if (!consented || state === "running") return;
    controller.current?.abort();
    controller.current = new AbortController();
    setState("running");
    setError("");
    setFindings([]);
    try {
      const result = await scanPwnedPasswords(eligible, controller.current.signal);
      setFindings(result);
      setState("done");
    } catch (cause) {
      if (controller.current.signal.aborted) return;
      setError(cause instanceof Error ? cause.message : "Breach scan failed.");
      setState("error");
    }
  }

  return (
    <>
      <div className="page-head"><h2>Data Breach Scanner</h2></div>
      <div className="card-section" style={{ maxWidth: 720, marginBottom: 16 }}>
        <p className="muted">
          Bastion hashes each distinct password locally and sends only the first five SHA-1
          characters to the Pwned Passwords range service. Full hashes and plaintext passwords
          never leave this browser. Results are not saved.
        </p>
        <label className="breach-consent">
          <input
            type="checkbox"
            checked={consented}
            onChange={(event) => setConsented(event.target.checked)}
          />
          I understand that {eligible.length} password {eligible.length === 1 ? "entry" : "entries"} will be checked using k-anonymous network requests.
        </label>
        <button
          className="btn btn-primary"
          disabled={!consented || state === "running" || eligible.length === 0}
          onClick={() => void scan()}
        >
          {state === "running" ? "Scanning…" : "Scan passwords"}
        </button>
        {eligible.length === 0 && <div className="faint" style={{ marginTop: 10 }}>No login passwords to scan.</div>}
        {error && <div className="callout" role="alert">{error}</div>}
      </div>

      <div role="status" aria-live="polite" className="faint" style={{ marginBottom: 12 }}>
        {state === "done" && (findings.length === 0
          ? "No compromised passwords were found."
          : `${findings.length} compromised password ${findings.length === 1 ? "entry" : "entries"} found.`)}
      </div>

      {findings.length > 0 && (
        <div className="card-section" style={{ maxWidth: 720 }}>
          <div className="health-section-title" style={{ color: "var(--danger)" }}>
            Compromised passwords
          </div>
          {findings.map(({ item, occurrences }) => (
            <button key={item.id} className="row-copy health-row" onClick={() => onOpen(item)}>
              <Favicon item={item} size={28} />
              <span className="v">{item.title}</span>
              <span className="faint health-meta">Seen {occurrences.toLocaleString()} times</span>
            </button>
          ))}
        </div>
      )}
    </>
  );
}
