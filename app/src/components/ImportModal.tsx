import { useMemo, useRef, useState, type JSX } from "react";
import {
  MAX_CSV_BYTES,
  csvToItems,
  type ImportOutcome,
  type ImportProgress,
  type ImportResult,
} from "../lib/import";
import { TYPE_LABEL, type ItemType } from "../lib/types";
import type { VaultItem } from "../lib/types";
import { partitionImportItems } from "../lib/import-dedup";
import { IcUpload } from "./icons";
import { Dialog } from "./Dialog";

export function ImportModal({
  onImport,
  onClose,
  existingItems,
}: {
  onImport: (result: ImportResult, onProgress: ImportProgress) => Promise<ImportOutcome>;
  onClose: () => void;
  existingItems: VaultItem[];
}): JSX.Element {
  const [result, setResult] = useState<ImportResult | null>(null);
  const [outcome, setOutcome] = useState<ImportOutcome | null>(null);
  const [progress, setProgress] = useState<ImportOutcome | null>(null);
  const [fileName, setFileName] = useState("");
  const [err, setErr] = useState("");
  const [reading, setReading] = useState(false);
  const [importing, setImporting] = useState(false);
  const [includeDuplicates, setIncludeDuplicates] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const chooseRef = useRef<HTMLButtonElement>(null);

  function handleFile(file: File) {
    setErr("");
    setFileName(file.name);
    setResult(null);
    setOutcome(null);
    setProgress(null);
    setIncludeDuplicates(false);
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
    if (!result || importing || selectedItems.length === 0) return;
    setErr("");
    setOutcome(null);
    setProgress({ imported: 0, requested: selectedItems.length });
    setImporting(true);
    try {
      const completed = await onImport({ ...result, items: selectedItems }, (imported, requested) => {
        setProgress({ imported, requested });
      });
      setOutcome(completed);
      setProgress(completed);
      // The import is over: drop the parsed plaintext (every password in the
      // CSV) from component state instead of holding it while the outcome
      // screen sits open. Retrying a partial import re-reads the file.
      setResult(null);
    } catch {
      setErr("The import did not complete. Unconfirmed items were not added.");
    } finally {
      setImporting(false);
    }
  }

  const partition = useMemo(
    () => result ? partitionImportItems(result.items, existingItems) : { unique: [], duplicates: [] },
    [existingItems, result]
  );
  const selectedItems = result
    ? includeDuplicates
      ? result.items
      : partition.unique
    : [];

  const counts = result
    ? selectedItems.reduce<Record<ItemType, number>>(
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
              disabled={!result || selectedItems.length === 0 || reading || importing}
              onClick={() => void startImport()}
            >
              {importing && progress
                ? `Importing ${progress.imported}/${progress.requested}…`
                : `Import ${result ? selectedItems.length : ""} items`}
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

          {err && <div className="callout callout-danger" role="alert" style={{ marginTop: 14 }}>{err}</div>}

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
              <div style={{ fontSize: 28, fontWeight: 800 }}>{selectedItems.length}</div>
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
              {partition.duplicates.length > 0 && (
                <>
                  <div className="faint" style={{ marginTop: 8, fontSize: 12 }}>
                    {partition.duplicates.length} exact duplicate(s) skipped by default.
                  </div>
                  <label className="send-check">
                    <input
                      type="checkbox"
                      checked={includeDuplicates}
                      disabled={importing}
                      onChange={(event) => setIncludeDuplicates(event.target.checked)}
                    />
                    Import exact duplicates anyway
                  </label>
                </>
              )}
            </div>
          )}
    </Dialog>
  );
}
