import { useRef, useState, type JSX } from "react";
import {
  MAX_CSV_BYTES,
  csvToItems,
  type ImportOutcome,
  type ImportProgress,
  type ImportResult,
} from "../lib/import";
import { TYPE_LABEL, type ItemType } from "../lib/types";
import { IcUpload } from "./icons";
import { Dialog } from "./Dialog";

export function ImportModal({
  onImport,
  onClose,
}: {
  onImport: (result: ImportResult, onProgress: ImportProgress) => Promise<ImportOutcome>;
  onClose: () => void;
}): JSX.Element {
  const [result, setResult] = useState<ImportResult | null>(null);
  const [outcome, setOutcome] = useState<ImportOutcome | null>(null);
  const [progress, setProgress] = useState<ImportOutcome | null>(null);
  const [fileName, setFileName] = useState("");
  const [err, setErr] = useState("");
  const [reading, setReading] = useState(false);
  const [importing, setImporting] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const chooseRef = useRef<HTMLButtonElement>(null);

  function handleFile(file: File) {
    setErr("");
    setFileName(file.name);
    setResult(null);
    setOutcome(null);
    setProgress(null);
    if (file.size > MAX_CSV_BYTES) {
      setErr("CSV files cannot exceed 5 MiB.");
      return;
    }
    setReading(true);
    const reader = new FileReader();
    reader.onerror = () => {
      setReading(false);
      setErr("Could not read the file.");
    };
    reader.onabort = reader.onerror;
    reader.onload = () => {
      try {
        const res = csvToItems(String(reader.result));
        if (res.items.length === 0) {
          setErr("No importable rows found in this CSV.");
          setResult(null);
          return;
        }
        setResult(res);
      } catch (error) {
        setErr(error instanceof Error ? error.message : "Could not parse this CSV file.");
        setResult(null);
      } finally {
        setReading(false);
      }
    };
    reader.readAsText(file);
  }

  async function startImport(): Promise<void> {
    if (!result || importing) return;
    setErr("");
    setOutcome(null);
    setProgress({ imported: 0, requested: result.items.length });
    setImporting(true);
    try {
      const completed = await onImport(result, (imported, requested) => {
        setProgress({ imported, requested });
      });
      setOutcome(completed);
      setProgress(completed);
    } catch {
      setErr("The import did not complete. Unconfirmed items were not added.");
    } finally {
      setImporting(false);
    }
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
      closeDisabled={reading || importing}
      initialFocusRef={chooseRef}
      footer={
        outcome ? (
          <>
            <span className="spacer" />
            <button className="btn btn-primary" onClick={onClose}>Close</button>
          </>
        ) : (
          <>
            <span className="spacer" />
            <button className="btn btn-ghost" disabled={reading || importing} onClick={onClose}>Cancel</button>
            <button
              className="btn btn-primary"
              disabled={!result || reading || importing}
              onClick={() => void startImport()}
            >
              {importing && progress
                ? `Importing ${progress.imported}/${progress.requested}…`
                : `Import ${result ? result.items.length : ""} items`}
            </button>
          </>
        )
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
            disabled={reading || importing}
            style={{ display: "none" }}
            onChange={(event) => {
              const file = event.currentTarget.files?.[0];
              event.currentTarget.value = "";
              if (file) handleFile(file);
            }}
          />
          <button ref={chooseRef} className="btn btn-block" disabled={reading || importing} onClick={() => inputRef.current?.click()}>
            <IcUpload size={16} /> {reading ? "Reading CSV…" : fileName || "Choose a CSV file"}
          </button>

          {err && <div className="callout" role="alert" style={{ marginTop: 14 }}>{err}</div>}

          {progress && !outcome && (
            <div className="import-progress" role="status" aria-live="polite">
              <progress aria-label="CSV import progress" value={progress.imported} max={progress.requested} />
              <span>{progress.imported} of {progress.requested} items confirmed</span>
            </div>
          )}

          {outcome && (
            <div className={`import-outcome${outcome.imported === outcome.requested ? " complete" : " partial"}`} role="status">
              <strong>Imported {outcome.imported} of {outcome.requested} items.</strong>
              <span>
                {outcome.imported === outcome.requested
                  ? "Every item was confirmed by the encrypted vault transaction."
                  : "Unconfirmed items were not added. You can close this dialog and retry them later."}
              </span>
            </div>
          )}

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
