import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { Welcome } from "./screens/Welcome";
import { RevealSecret } from "./screens/RevealSecret";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { ensureWasm, register, unlock, type Account } from "./lib/wasm";
import { api, ApiError, type Blob, type Registration } from "./lib/api";
import { SEND_IDENTITY_ID, loadContacts, type Contact } from "./lib/send";
import type { VaultItem } from "./lib/types";

type Phase = "welcome" | "reveal" | "unlock" | "vault";

const AUTO_LOCK_MS = 10 * 60 * 1000; // lock after 10 minutes of inactivity
const HIDDEN_GRACE_MS = 30 * 1000; // lock 30s after the tab is actually hidden

/** Vault items under this prefix hold Bastion Send state (identity, contacts),
 * not user entries — never surface them in the vault list. */
const isReservedItem = (id: string): boolean => id.startsWith("bastion:send-");

function loadItems(account: Account, items: Record<string, Blob>): VaultItem[] {
  const out: VaultItem[] = [];
  for (const [id, blob] of Object.entries(items)) {
    if (isReservedItem(id)) continue; // Bastion Send state, not a vault entry
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
  const [sendContacts, setSendContacts] = useState<Contact[]>([]);
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);
  const sessionEpoch = useRef(0);

  const toast = useCallback((m: string) => {
    setToastMsg(m);
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToastMsg(null), 2200);
  }, []);

  const lock = useCallback(() => {
    sessionEpoch.current += 1;
    if (token) api.logout(token).catch(() => {});
    account?.lock(); // drops + zeroizes the vault key in WASM
    setAccount(null);
    setToken(null);
    setItems([]); // plaintext cleared; reloaded from the server on next unlock
    setSendContacts([]);
    setPhase("unlock");
  }, [account, token]);

  // Auto-lock on prolonged inactivity, or after the tab has been genuinely
  // hidden for a grace period. We deliberately do NOT lock on window `blur`
  // (it fires for the address bar, extensions, autofill, screenshots…), which
  // would kick the user out constantly.
  useEffect(() => {
    if (phase !== "vault") return;
    let idle = window.setTimeout(lock, AUTO_LOCK_MS);
    let hideTimer: number | undefined;
    const reset = () => {
      window.clearTimeout(idle);
      idle = window.setTimeout(lock, AUTO_LOCK_MS);
    };
    const onVis = () => {
      if (document.visibilityState === "hidden") {
        hideTimer = window.setTimeout(lock, HIDDEN_GRACE_MS);
      } else {
        window.clearTimeout(hideTimer);
      }
    };
    const acts = ["mousemove", "keydown", "click", "scroll", "touchstart"];
    acts.forEach((e) => window.addEventListener(e, reset, { passive: true }));
    document.addEventListener("visibilitychange", onVis);
    return () => {
      window.clearTimeout(idle);
      window.clearTimeout(hideTimer);
      acts.forEach((e) => window.removeEventListener(e, reset));
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [phase, lock]);

  // ── create a new vault locally; persist only after the recovery key is saved ──
  const onCreate = useCallback(async (em: string, pw: string) => {
    await ensureWasm();
    const acc = register(pw);
    setAccount(acc);
    setEmail(em);
    setToken(null);
    setItems([]);
    setPhase("reveal");
  }, []);

  const finishCreate = useCallback(async () => {
    if (!account) throw new Error("The local vault is no longer available. Start again.");
    const registration = JSON.parse(account.registration_json) as Registration;
    let collided = false;
    try {
      await api.createAccount(email, registration);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) collided = true;
      else throw e;
    }
    let tok: string;
    try {
      // Login after both a fresh create and a conflict. A conflict can be the
      // idempotent retry of our own create after its response was lost.
      tok = await api.login(email, account.auth_secret);
    } catch (e) {
      if (collided && e instanceof ApiError && e.status === 401) {
        throw new Error('An account with this email already exists. Use "Unlock an existing vault".');
      }
      throw new Error(
        "Your vault may already be created, and your saved Secret Key keeps it recoverable. Retry, or unlock the existing vault."
      );
    }
    setToken(tok);
    setPhase("vault");
  }, [account, email]);

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
    // Load the Send identity (if enabled) so has_send_identity works; it's a
    // reserved item, kept out of the vault list by loadItems.
    const idItem = vault.items[SEND_IDENTITY_ID];
    if (idItem) {
      try {
        acc.load_send_identity(JSON.stringify(idItem));
      } catch {
        /* malformed reserved item */
      }
    }
    setAccount(acc);
    setEmail(em);
    setToken(tok);
    setItems(loadItems(acc, vault.items));
    setSendContacts(loadContacts(acc, vault.items));
    setPhase("vault");
  }, []);

  // ── item mutations (encrypt + persist first, then commit visible state) ──
  const upsert = useCallback(
    async (item: VaultItem): Promise<boolean> => {
      if (!account || !token) {
        toast("Vault is locked — item was not saved");
        return false;
      }
      const epoch = sessionEpoch.current;
      try {
        const blob = JSON.parse(account.encrypt_item(JSON.stringify(item), item.id)) as Blob;
        await api.putItem(token, item.id, blob);
        if (sessionEpoch.current !== epoch) return true;
        setItems((prev) => {
          const i = prev.findIndex((x) => x.id === item.id);
          if (i === -1) return [item, ...prev];
          const next = prev.slice();
          next[i] = item;
          return next;
        });
        return true;
      } catch {
        toast("Save failed — item was not changed");
        return false;
      }
    },
    [account, token, toast]
  );

  const remove = useCallback(
    async (id: string): Promise<boolean> => {
      if (!token) {
        toast("Vault is locked — item was not deleted");
        return false;
      }
      const epoch = sessionEpoch.current;
      try {
        await api.deleteItem(token, id);
        if (sessionEpoch.current !== epoch) return true;
        setItems((prev) => prev.filter((x) => x.id !== id));
        return true;
      } catch {
        toast("Delete failed — item was not changed");
        return false;
      }
    },
    [token, toast]
  );

  // ── bulk import (CSV): expose only items confirmed by the server ──
  const importItems = useCallback(
    async ({ items: imported }: { items: VaultItem[] }) => {
      if (imported.length === 0) return;
      if (!account || !token) {
        toast("Vault is locked — nothing was imported");
        return;
      }
      toast(`Importing ${imported.length} items…`);
      const epoch = sessionEpoch.current;
      const queue = imported.slice();
      const persisted: VaultItem[] = [];
      const worker = async () => {
        while (queue.length) {
          const it = queue.shift()!;
          try {
            const blob = JSON.parse(account.encrypt_item(JSON.stringify(it), it.id)) as Blob;
            await api.putItem(token, it.id, blob);
            persisted.push(it);
          } catch {
            /* keep going; report total at the end */
          }
        }
      };
      await Promise.all(Array.from({ length: 8 }, worker));
      if (sessionEpoch.current !== epoch) return;
      setItems((prev) => {
        const next = new Map(prev.map((item) => [item.id, item]));
        persisted.forEach((item) => next.set(item.id, item));
        return [...next.values()].sort((a, b) => b.updatedAt - a.updatedAt);
      });
      toast(
        persisted.length === imported.length
          ? `Imported ${persisted.length} items`
          : `Imported ${persisted.length}/${imported.length} (failed items were not added)`
      );
    },
    [account, token, toast]
  );

  return (
    <>
      {phase === "welcome" && <Welcome onCreate={onCreate} onHaveVault={() => setPhase("unlock")} />}
      {phase === "reveal" && account && (
        <RevealSecret account={account} toast={toast} onDone={finishCreate} />
      )}
      {phase === "unlock" && <Unlock onUnlock={onUnlock} onCreateNew={() => setPhase("welcome")} />}
      {phase === "vault" && (
        <Vault
          email={email}
          items={items}
          account={account}
          token={token}
          sendContacts={sendContacts}
          setSendContacts={setSendContacts}
          onUpsert={upsert}
          onDelete={remove}
          onImport={importItems}
          onLock={lock}
          toast={toast}
        />
      )}
      {toastMsg && <div className="toast">{toastMsg}</div>}
    </>
  );
}
