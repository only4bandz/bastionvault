import { useEffect, useState, type JSX } from "react";
import {
  BITS_PER_WORD,
  generatePassphrase,
  generatePassword,
  MAX_PASSPHRASE_WORDS,
  MIN_PASSPHRASE_WORDS,
  passphraseBits,
  strength,
  type GenOptions,
  type PassphraseOptions,
} from "../lib/generator";
import { copySecretWithFeedback } from "../lib/clipboard";
import { IcCopy, IcEye, IcRefresh } from "./icons";

const DEFAULTS: GenOptions = {
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: true,
};

const PHRASE_DEFAULTS: PassphraseOptions = {
  words: 5,
  separator: "-",
  capitalize: false,
  includeNumber: false,
};

type Mode = "characters" | "words";

/** Map passphrase entropy (bits) onto the shared 0..4 strength scale. */
function phraseScore(bits: number): { score: number; label: string; color: string } {
  const score = bits < 36 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  const colors = ["#ff5d6c", "#ff5d6c", "#ffb454", "#3ad29f", "#3ad29f"];
  return { score, label: `${labels[score]} · ~${Math.round(bits)} bits`, color: colors[score] };
}

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
  const [mode, setMode] = useState<Mode>("characters");
  const [opts, setOpts] = useState<GenOptions>(DEFAULTS);
  const [phraseOpts, setPhraseOpts] = useState<PassphraseOptions>(PHRASE_DEFAULTS);
  const [pw, setPw] = useState("");
  // A freshly generated password is as sensitive as a stored one: it is about
  // to become a credential. The item detail view and the Emergency Kit both
  // conceal on blur/tab-hide for the shoulder-surfer, screen-share and screen
  // recorder cases; a candidate left legible in an unfocused window is the
  // same exposure, and the app's hidden-tab lock only fires after 30s.
  const [concealed, setConcealed] = useState(false);

  function regen(m = mode, o = opts, p = phraseOpts) {
    setPw(m === "characters" ? generatePassword(o) : generatePassphrase(p));
    setConcealed(false); // a value the user just asked for is shown
  }
  useEffect(() => {
    regen("characters", DEFAULTS);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const conceal = (): void => setConcealed(true);
    const onVisibilityChange = (): void => {
      if (document.visibilityState === "hidden") conceal();
    };
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("blur", conceal);
    window.addEventListener("pagehide", conceal);
    return () => {
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("blur", conceal);
      window.removeEventListener("pagehide", conceal);
    };
  }, []);

  function set<K extends keyof GenOptions>(k: K, v: GenOptions[K]) {
    const next = { ...opts, [k]: v };
    // keep at least one class enabled
    if (!next.lower && !next.upper && !next.digits && !next.symbols) return;
    setOpts(next);
    regen(mode, next);
  }

  function setPhrase<K extends keyof PassphraseOptions>(k: K, v: PassphraseOptions[K]) {
    const next = { ...phraseOpts, [k]: v };
    setPhraseOpts(next);
    regen(mode, opts, next);
  }

  function switchMode(m: Mode) {
    if (m === mode) return;
    setMode(m);
    regen(m);
  }

  const s = mode === "characters" ? strength(pw) : phraseScore(passphraseBits(phraseOpts));
  const label = mode === "characters" ? "Password" : "Passphrase";

  return (
    <div className="gen">
      <div className="tabs" role="tablist" aria-label="Generator mode" style={{ marginBottom: 4 }}>
        {(
          [
            ["characters", "Characters"],
            ["words", "Words"],
          ] as [Mode, string][]
        ).map(([m, text]) => (
          <button
            key={m}
            role="tab"
            aria-selected={mode === m}
            className={`tab${mode === m ? " active" : ""}`}
            onClick={() => switchMode(m)}
          >
            {text}
          </button>
        ))}
      </div>

      <div className="gen-out">
        <span className="val mono">
          {pw ? (concealed ? "•".repeat(Math.min(pw.length, 24)) : pw) : "—"}
        </span>
        {pw && concealed && (
          <button
            className="icon-btn"
            aria-label={`Show generated ${label.toLowerCase()}`}
            onClick={() => setConcealed(false)}
          >
            <IcEye size={17} />
          </button>
        )}
        <button className="icon-btn" aria-label={`Regenerate ${label.toLowerCase()}`} onClick={() => regen()}>
          <IcRefresh size={17} />
        </button>
        <button
          className="icon-btn"
          aria-label={`Copy generated ${label.toLowerCase()}`}
          onClick={() => void copySecretWithFeedback(pw, label, toast)}
        >
          <IcCopy size={17} />
        </button>
      </div>
      <div
        className="strength strength-steps"
        role="meter"
        aria-label={`${label} strength`}
        aria-valuemin={0}
        aria-valuemax={4}
        aria-valuenow={s.score}
        aria-valuetext={s.label}
      >
        <i style={{ width: `${(s.score / 4) * 100}%`, background: s.color }} />
      </div>
      <div className="faint" style={{ fontSize: 12, marginTop: -8 }}>{s.label}</div>

      {mode === "characters" ? (
        <>
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
        </>
      ) : (
        <>
          <div className="slider-row">
            <span className="muted" style={{ fontSize: 13 }}>Words</span>
            <input
              type="range"
              aria-label="Number of words"
              min={MIN_PASSPHRASE_WORDS}
              max={MAX_PASSPHRASE_WORDS}
              value={phraseOpts.words}
              onChange={(e) => setPhrase("words", Number(e.target.value))}
            />
            <span className="mono" style={{ width: 26, textAlign: "right" }}>{phraseOpts.words}</span>
          </div>

          <div>
            <div className="toggle-row">
              <span>Separator</span>
              <span style={{ display: "flex", gap: 6 }}>
                {(["-", ".", "_", " "] as const).map((sep) => (
                  <button
                    key={sep}
                    className={`tab${phraseOpts.separator === sep ? " active" : ""}`}
                    aria-pressed={phraseOpts.separator === sep}
                    aria-label={`Separator ${sep === " " ? "space" : sep}`}
                    style={{ minWidth: 34 }}
                    onClick={() => setPhrase("separator", sep)}
                  >
                    <span className="mono">{sep === " " ? "␣" : sep}</span>
                  </button>
                ))}
              </span>
            </div>
            <div className="toggle-row"><span>Capitalize words</span><Toggle label="Capitalize words" on={phraseOpts.capitalize} onClick={() => setPhrase("capitalize", !phraseOpts.capitalize)} /></div>
            <div className="toggle-row"><span>Include a digit</span><Toggle label="Include a digit" on={phraseOpts.includeNumber} onClick={() => setPhrase("includeNumber", !phraseOpts.includeNumber)} /></div>
          </div>
          <div className="faint" style={{ fontSize: 12 }}>
            {phraseOpts.words} words × {BITS_PER_WORD.toFixed(0)} bits from a 2,048-word list.
            Easier to type and remember than symbol soup, same math.
          </div>
        </>
      )}

      {onUse && (
        <button className="btn btn-primary btn-block" onClick={() => onUse(pw)}>
          Use this {label.toLowerCase()}
        </button>
      )}
    </div>
  );
}
