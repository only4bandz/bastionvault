import { useRef, useState, type JSX } from "react";
import { csvToItems, type ImportResult } from "../lib/import";
import { TYPE_LABEL, type ItemType } from "../lib/types";
import { IcUpload } from "./icons";
import { Dialog } from "./Dialog";

export function ImportModal({
  onImport,
  onClose,
}: {
  onImport: (result: ImportResult) => void;
  onClose: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ImportResult | null>(null);
  const [fileName, setFileName] = useState("");
  const [err, setErr] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const chooseRef = useRef<HTMLButtonElement>(null);

  function handleFile(file: File) {
    setErr("");
    setFileName(file.name);
    const reader = new FileReader();
    reader.onerror = () => setErr("Could not read the file.");
    reader.onload = () => {
      try {
        const res = csvToItems(String(reader.result));
        if (res.items.length === 0) {
          setErr("No importable rows found in this CSV.");
          setResult(null);
          return;
        }
        setResult(res);
      } catch {
        setErr("Could not parse this CSV file.");
        setResult(null);
      }
    };
    reader.readAsText(file);
  }

  const counts = result
    ? result.items.reduce<Record<ItemType, number>>(
        (acc, it) => ((acc[it.type] = (acc[it.type] || 0) + 1), acc),
        { login: 0, note: 0, card: 0 }
      )
    : null;

  return (
    <Dialog
      title="Import from CSV"
      onClose={onClose}
      initialFocusRef={chooseRef}
      footer={
        <>
          <span className="spacer" />
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button
            className="btn btn-primary"
            disabled={!result}
            onClick={() => result && onImport(result)}
          >
            Import {result ? result.items.length : ""} items
          </button>
        </>
      }
    >
          <p className="muted" style={{ marginTop: 0, fontSize: 13 }}>
            Import a CSV export from NordPass, Bitwarden, 1Password, LastPass and
            others. Everything is encrypted on this device before syncing — the
            server never sees your passwords in plaintext.
          </p>

          <input
            ref={inputRef}
            type="file"
            accept=".csv,text/csv"
            style={{ display: "none" }}
            onChange={(e) => e.target.files?.[0] && handleFile(e.target.files[0])}
          />
          <button ref={chooseRef} className="btn btn-block" onClick={() => inputRef.current?.click()}>
            <IcUpload size={16} /> {fileName || "Choose a CSV file"}
          </button>

          {err && <div className="callout" style={{ marginTop: 14 }}>{err}</div>}

          {result && counts && (
            <div className="card-section" style={{ marginTop: 16, maxWidth: "none" }}>
              <div style={{ fontSize: 28, fontWeight: 800 }}>{result.items.length}</div>
              <div className="muted" style={{ marginBottom: 10 }}>items ready to import</div>
              {(["login", "note", "card"] as ItemType[]).map((t) =>
                counts[t] ? (
                  <div className="row-copy" key={t}>
                    <span className="k">{TYPE_LABEL[t]}</span>
                    <span className="v mono">{counts[t]}</span>
                  </div>
                ) : null
              )}
              {result.skipped > 0 && (
                <div className="faint" style={{ marginTop: 8, fontSize: 12 }}>
                  {result.skipped} row(s) skipped (no name).
                </div>
              )}
            </div>
          )}
    </Dialog>
  );
}
