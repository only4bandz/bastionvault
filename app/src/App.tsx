import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { Welcome } from "./screens/Welcome";
import { RevealSecret } from "./screens/RevealSecret";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import type { Account } from "./lib/wasm";
import type { VaultItem } from "./lib/types";

type Phase = "welcome" | "reveal" | "unlock" | "vault";

const AUTO_LOCK_MS = 8 * 60 * 1000; // lock after 8 minutes of inactivity

export default function App(): JSX.Element {
  const [phase, setPhase] = useState<Phase>("welcome");
  const [account, setAccount] = useState<Account | null>(null);
  const [registrationJson, setRegistrationJson] = useState<string | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const toast = useCallback((m: string) => {
    setToastMsg(m);
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToastMsg(null), 1800);
  }, []);

  const lock = useCallback(() => {
    account?.lock(); // drops + zeroizes the vault key in WASM
    setAccount(null);
    setPhase("unlock");
  }, [account]);

  // Auto-lock on inactivity + when the tab is hidden/blurred.
  useEffect(() => {
    if (phase !== "vault") return;
    let timer = window.setTimeout(lock, AUTO_LOCK_MS);
    const reset = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(lock, AUTO_LOCK_MS);
    };
    const onHidden = () => document.visibilityState === "hidden" && lock();
    const acts = ["mousemove", "keydown", "click", "scroll"];
    acts.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    document.addEventListener("visibilitychange", onHidden);
    window.addEventListener("blur", lock);
    return () => {
      window.clearTimeout(timer);
      acts.forEach((e) => window.removeEventListener(e, reset));
      document.removeEventListener("visibilitychange", onHidden);
      window.removeEventListener("blur", lock);
    };
  }, [phase, lock]);

  function onCreated(acc: Account) {
    setAccount(acc);
    setRegistrationJson(acc.registration_json);
    setPhase("reveal");
  }

  function onUnlocked(acc: Account) {
    setAccount(acc);
    setPhase("vault");
  }

  function upsert(item: VaultItem) {
    setItems((prev) => {
      const i = prev.findIndex((x) => x.id === item.id);
      if (i === -1) return [item, ...prev];
      const next = prev.slice();
      next[i] = item;
      return next;
    });
  }
  const remove = (id: string) => setItems((prev) => prev.filter((x) => x.id !== id));

  return (
    <>
      {phase === "welcome" && (
        <Welcome
          onCreated={onCreated}
          onHaveVault={() =>
            registrationJson
              ? setPhase("unlock")
              : toast("Create a vault first — multi-device sign-in comes with sync.")
          }
        />
      )}
      {phase === "reveal" && account && (
        <RevealSecret account={account} toast={toast} onDone={() => setPhase("vault")} />
      )}
      {phase === "unlock" && registrationJson && (
        <Unlock registrationJson={registrationJson} onUnlocked={onUnlocked} />
      )}
      {phase === "vault" && (
        <Vault items={items} onUpsert={upsert} onDelete={remove} onLock={lock} toast={toast} />
      )}

      {toastMsg && <div className="toast">{toastMsg}</div>}
    </>
  );
}
