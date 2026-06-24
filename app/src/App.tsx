import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { Welcome } from "./screens/Welcome";
import { RevealSecret } from "./screens/RevealSecret";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { ensureWasm, register, unlock, type Account } from "./lib/wasm";
import { api, ApiError, type Blob, type Registration } from "./lib/api";
import type { VaultItem } from "./lib/types";

type Phase = "welcome" | "reveal" | "unlock" | "vault";

const AUTO_LOCK_MS = 8 * 60 * 1000; // lock after 8 minutes of inactivity

function loadItems(account: Account, items: Record<string, Blob>): VaultItem[] {
  const out: VaultItem[] = [];
  for (const [id, blob] of Object.entries(items)) {
    try {
      out.push(JSON.parse(account.decrypt_item(JSON.stringify(blob), id)) as VaultItem);
    } catch {
      // Skip an item that fails to decrypt (corrupt / tampered).
    }
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

export default function App(): JSX.Element {
  const [phase, setPhase] = useState<Phase>("welcome");
  const [account, setAccount] = useState<Account | null>(null);
  const [email, setEmail] = useState("");
  const [token, setToken] = useState<string | null>(null);
  const [items, setItems] = useState<VaultItem[]>([]);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const toast = useCallback((m: string) => {
    setToastMsg(m);
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToastMsg(null), 2200);
  }, []);

  const lock = useCallback(() => {
    if (token) api.logout(token).catch(() => {});
    account?.lock(); // drops + zeroizes the vault key in WASM
    setAccount(null);
    setToken(null);
    setItems([]); // plaintext cleared; reloaded from the server on next unlock
    setPhase("unlock");
  }, [account, token]);

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

  // ── create a new vault, persisted on the server ──
  const onCreate = useCallback(async (em: string, pw: string) => {
    await ensureWasm();
    const acc = register(pw);
    const registration = JSON.parse(acc.registration_json) as Registration;
    try {
      await api.createAccount(em, registration);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409)
        throw new Error('An account with this email already exists. Use "Unlock an existing vault".');
      throw e;
    }
    const tok = await api.login(em, acc.auth_secret);
    setAccount(acc);
    setEmail(em);
    setToken(tok);
    setItems([]);
    setPhase("reveal");
  }, []);

  // ── unlock an existing vault from the server ──
  const onUnlock = useCallback(async (em: string, pw: string, secretKey: string) => {
    await ensureWasm();
    const pre = await api.prelogin(em).catch((e) => {
      if (e instanceof ApiError && e.status === 404) throw new Error("No vault found for this email.");
      throw e;
    });
    // unlock() only needs salt/kdf/wrapped key; auth_secret is re-derived inside.
    const regJson = JSON.stringify({
      version: 1,
      salt: pre.salt,
      kdf: pre.kdf,
      wrapped_vault_key: pre.wrapped_vault_key,
      auth_secret: "",
    });
    let acc: Account;
    try {
      acc = unlock(pw, secretKey, regJson);
    } catch {
      throw new Error("Invalid master password or Secret Key.");
    }
    const tok = await api.login(em, acc.auth_secret);
    const vault = await api.getVault(tok);
    setAccount(acc);
    setEmail(em);
    setToken(tok);
    setItems(loadItems(acc, vault.items));
    setPhase("vault");
  }, []);

  // ── item mutations (optimistic local + encrypted push to server) ──
  const upsert = useCallback(
    (item: VaultItem) => {
      setItems((prev) => {
        const i = prev.findIndex((x) => x.id === item.id);
        if (i === -1) return [item, ...prev];
        const next = prev.slice();
        next[i] = item;
        return next;
      });
      if (account && token) {
        try {
          const blob = JSON.parse(account.encrypt_item(JSON.stringify(item), item.id)) as Blob;
          api.putItem(token, item.id, blob).catch(() => toast("Saved locally — server sync failed"));
        } catch {
          toast("Could not encrypt item");
        }
      }
    },
    [account, token, toast]
  );

  const remove = useCallback(
    (id: string) => {
      setItems((prev) => prev.filter((x) => x.id !== id));
      if (token) api.deleteItem(token, id).catch(() => toast("Deleted locally — server sync failed"));
    },
    [token, toast]
  );

  return (
    <>
      {phase === "welcome" && <Welcome onCreate={onCreate} onHaveVault={() => setPhase("unlock")} />}
      {phase === "reveal" && account && (
        <RevealSecret account={account} toast={toast} onDone={() => setPhase("vault")} />
      )}
      {phase === "unlock" && <Unlock onUnlock={onUnlock} onCreateNew={() => setPhase("welcome")} />}
      {phase === "vault" && (
        <Vault
          email={email}
          items={items}
          onUpsert={upsert}
          onDelete={remove}
          onLock={lock}
          toast={toast}
        />
      )}
      {toastMsg && <div className="toast">{toastMsg}</div>}
    </>
  );
}
