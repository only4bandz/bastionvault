import { useState, type InputHTMLAttributes, type JSX } from "react";
import { IcEye } from "./icons";

export function SecretInput({
  label,
  className = "",
  ...inputProps
}: Omit<InputHTMLAttributes<HTMLInputElement>, "type"> & {
  label: string;
}): JSX.Element {
  const [revealed, setRevealed] = useState(false);

  return (
    <div className="secret-input">
      <input
        {...inputProps}
        // Secrets must never reach cloud spell-checkers, autocorrect
        // dictionaries, or IME suggestion logs — especially while revealed as
        // type="text" ("spell-jacking"). Placed after the spread so callers
        // cannot weaken them.
        spellCheck={false}
        autoCorrect="off"
        autoCapitalize="none"
        className={`input${className ? ` ${className}` : ""}`}
        type={revealed ? "text" : "password"}
      />
      <button
        className="icon-btn secret-toggle"
        type="button"
        aria-label={`${revealed ? "Hide" : "Show"} ${label.toLowerCase()}`}
        aria-pressed={revealed}
        onClick={() => setRevealed((visible) => !visible)}
      >
        <IcEye size={16} />
      </button>
    </div>
  );
}
