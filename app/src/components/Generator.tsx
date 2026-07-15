import { useEffect, useState, type JSX } from "react";
import { generatePassword, strength, type GenOptions } from "../lib/generator";
import { IcCopy, IcRefresh } from "./icons";

const DEFAULTS: GenOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
};

function Toggle({ label, on, onClick }: { label: string; on: boolean; onClick: () => void }) {
  return <button className={`switch${on ? " on" : ""}`} aria-label={label} onClick={onClick} aria-pressed={on} />;
}

export function Generator({
  onUse,
  toast,
}: {
  onUse?: (pw: string) => void;
  toast: (m: string) => void;
}): JSX.Element {
  const [opts, setOpts] = useState<GenOptions>(DEFAULTS);
  const [pw, setPw] = useState("");

  function regen(o = opts) {
    setPw(generatePassword(o));
  }
  useEffect(() => {
    regen(DEFAULTS);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function set<K extends keyof GenOptions>(k: K, v: GenOptions[K]) {
    const next = { ...opts, [k]: v };
    // keep at least one class enabled
    if (!next.lower && !next.upper && !next.digits && !next.symbols) return;
    setOpts(next);
    regen(next);
  }

  const s = strength(pw);

  return (
    <div className="gen">
      <div className="gen-out">
        <span className="val mono">{pw || "—"}</span>
        <button className="icon-btn" aria-label="Regenerate password" onClick={() => regen()}>
          <IcRefresh size={17} />
        </button>
        <button
          className="icon-btn"
          aria-label="Copy generated password"
          onClick={() => {
            navigator.clipboard?.writeText(pw);
            toast("Password copied");
          }}
        >
          <IcCopy size={17} />
        </button>
      </div>
      <div className="strength">
        <i style={{ width: `${(s.score / 4) * 100}%`, background: s.color }} />
      </div>
      <div className="faint" style={{ fontSize: 12, marginTop: -8 }}>{s.label}</div>

      <div className="slider-row">
        <span className="muted" style={{ fontSize: 13 }}>Length</span>
        <input
          type="range"
          aria-label="Password length"
          min={8}
          max={64}
          value={opts.length}
          onChange={(e) => set("length", Number(e.target.value))}
        />
        <span className="mono" style={{ width: 26, textAlign: "right" }}>{opts.length}</span>
      </div>

      <div>
        <div className="toggle-row"><span>Uppercase (A–Z)</span><Toggle label="Include uppercase letters" on={opts.upper} onClick={() => set("upper", !opts.upper)} /></div>
        <div className="toggle-row"><span>Lowercase (a–z)</span><Toggle label="Include lowercase letters" on={opts.lower} onClick={() => set("lower", !opts.lower)} /></div>
        <div className="toggle-row"><span>Digits (0–9)</span><Toggle label="Include digits" on={opts.digits} onClick={() => set("digits", !opts.digits)} /></div>
        <div className="toggle-row"><span>Symbols (!@#…)</span><Toggle label="Include symbols" on={opts.symbols} onClick={() => set("symbols", !opts.symbols)} /></div>
        <div className="toggle-row"><span>Avoid ambiguous (0/O, 1/l)</span><Toggle label="Avoid ambiguous characters" on={opts.avoidAmbiguous} onClick={() => set("avoidAmbiguous", !opts.avoidAmbiguous)} /></div>
      </div>

      {onUse && (
        <button className="btn btn-primary btn-block" onClick={() => onUse(pw)}>
          Use this password
        </button>
      )}
    </div>
  );
}
