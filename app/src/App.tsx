import { useCallback, useEffect, useRef, useState, type JSX } from "react";
import { Welcome } from "./screens/Welcome";
import { RevealSecret } from "./screens/RevealSecret";
import { Unlock } from "./screens/Unlock";
import { Vault } from "./screens/Vault";
import { ensureWasm, register, unlock, type Account } from "./lib/wasm";
import {
  api,
  ApiError,
  type Blob,
  type Registration,
  type VaultData,
  type VaultOperation,
} from "./lib/api";
import { SEND_CONTACTS_ID, SEND_IDENTITY_ID, loadContacts, type Contact } from "./lib/send";
import type { VaultItem } from "./lib/types";
import type { ImportOutcome, ImportProgress, ImportResult } from "./lib/import";
import {
  completeBootstrap,
  completeVaultMutation,
  prepareBootstrapManifest,
  prepareVaultMutation,
  reconcileVaultMutation,
  verifyVaultSnapshot,
  type VaultIntegrityState,
} from "./lib/vault-integrity";
import {
  VaultRollbackError,
  assertVaultRollbackProgress,
  createVaultRollbackAnchor,
  readVaultRollbackAnchor,
  vaultRollbackAnchorKey,
  withVaultRollbackLock,
  writeVaultRollbackAnchor,
  type AnchorStorage,
  type VaultRollbackAnchor,
} from "./lib/vault-anchor";

type Phase = "welcome" | "reveal" | "unlock" | "vault";

const AUTO_LOCK_MS = 10 * 60 * 1000; // lock after 10 minutes of inactivity
const HIDDEN_GRACE_MS = 30 * 1000; // lock 30s after the tab is actually hidden

/** Vault items under this prefix hold Bastion Send state (identity, contacts),
 * not user entries — never surface them in the vault list. */
const SEND_LOCKED_PREFIX = "bastion:send-locked:";
const OPTIONAL_ITEM_STRINGS: (keyof VaultItem)[] = [
  "username", "password", "url", "cardNumber", "cardExp", "cardCvv",
  "cardBrand", "cardBank", "cardBankDomain", "cardType", "notes",
];

function loadItems(account: Account, items: Record<string, Blob>): VaultItem[] {
  const out: VaultItem[] = [];
  for (const [id, blob] of Object.entries(items)) {
    if (id === SEND_IDENTITY_ID) continue; // validated by load_send_identity before this call
    try {
      const item: unknown = JSON.parse(account.decrypt_item(JSON.stringify(blob), id));
      if (id === SEND_CONTACTS_ID || id.startsWith(SEND_LOCKED_PREFIX)) {
        if (id === SEND_CONTACTS_ID ? !Array.isArray(item) : !item || typeof item !== "object") {
          throw new Error("invalid reserved item payload");
        }
        continue;
      }
      if (id.startsWith("bastion:send-")) throw new Error("unsupported reserved item");
      if (
        !item ||
        typeof item !== "object" ||
        (item as VaultItem).id !== id ||
        !["login", "note", "card"].includes((item as VaultItem).type) ||
        typeof (item as VaultItem).title !== "string" ||
        !Number.isFinite((item as VaultItem).updatedAt) ||
        OPTIONAL_ITEM_STRINGS.some(
          (field) => (item as VaultItem)[field] !== undefined && typeof (item as VaultItem)[field] !== "string"
        ) ||
        ((item as VaultItem).favorite !== undefined && typeof (item as VaultItem).favorite !== "boolean")
      ) {
        throw new Error("invalid item payload");
      }
      out.push(item as VaultItem);
    } catch {
      throw new Error("Encrypted vault integrity check failed. No items were loaded.");
    }
  }
  return out.sort((a, b) => b.updatedAt - a.updatedAt);
}

function decryptVaultState(
  account: Account,
  encryptedItems: Record<string, Blob>
): { items: VaultItem[]; contacts: Contact[] } {
  const identity = encryptedItems[SEND_IDENTITY_ID];
  if (identity) account.load_send_identity(JSON.stringify(identity));
  return {
    items: loadItems(account, encryptedItems),
    contacts: loadContacts(account, encryptedItems),
  };
}

async function establishVaultIntegrity(
  account: Account,
  token: string,
  vault: VaultData,
  trustedAnchor: VaultRollbackAnchor | null
): Promise<{
  integrity: VaultIntegrityState;
  rollbackAnchor: VaultRollbackAnchor;
  items: VaultItem[];
  contacts: Contact[];
  bootstrapped: boolean;
}> {
  if (vault.manifest) {
    const integrity = verifyVaultSnapshot(account, vault, trustedAnchor?.manifestSeq);
    const rollbackAnchor = await createVaultRollbackAnchor(integrity);
    assertVaultRollbackProgress(rollbackAnchor, trustedAnchor);
    return {
      integrity,
      rollbackAnchor,
      ...decryptVaultState(account, vault.items),
      bootstrapped: false,
    };
  }
  if (trustedAnchor) {
    throw new VaultRollbackError("A trusted vault manifest is missing from the server snapshot.");
  }

  // Legacy migration is explicit trust-on-first-use: every encrypted payload
  // must decrypt and validate before the first manifest is committed.
  const decrypted = decryptVaultState(account, vault.items);
  const bootstrap = prepareBootstrapManifest(account, vault);
  const result = await api.mutateVault(token, vault.revision, [], bootstrap.manifest);
  const integrity = completeBootstrap(account, vault, bootstrap, result.revision);
  return {
    integrity,
    rollbackAnchor: await createVaultRollbackAnchor(integrity),
    ...decrypted,
    bootstrapped: true,
  };
}

function browserAnchorStorage(): AnchorStorage {
  return window.localStorage; // storage-guard:allow -- non-secret rollback metadata only
}

function rollbackAnchorKey(accountId: string): string {
  const apiScope = new URL("/api", window.location.href).href;
  return vaultRollbackAnchorKey(apiScope, accountId);
}

async function establishVaultIntegrityAnchored(
  account: Account,
  accountId: string,
  token: string,
  vault: VaultData
): Promise<Awaited<ReturnType<typeof establishVaultIntegrity>>> {
  const key = rollbackAnchorKey(accountId);
  return withVaultRollbackLock(key, async () => {
    const storage = browserAnchorStorage();
    const trusted = readVaultRollbackAnchor(storage, key);
    const opened = await establishVaultIntegrity(account, token, vault, trusted);
    writeVaultRollbackAnchor(storage, key, opened.rollbackAnchor);
    return opened;
  });
}

async function persistVaultIntegrityAnchor(
  accountId: string,
  integrity: VaultIntegrityState
): Promise<void> {
  const key = rollbackAnchorKey(accountId);
  const candidate = await createVaultRollbackAnchor(integrity);
  await withVaultRollbackLock(key, async () => {
    writeVaultRollbackAnchor(browserAnchorStorage(), key, candidate);
  });
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
  const integrityRef = useRef<VaultIntegrityState | null>(null);
  const mutationTail = useRef<Promise<void>>(Promise.resolve());

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
    integrityRef.current = null;
    mutationTail.current = Promise.resolve();
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
    try {
      const vault = await api.getVault(tok);
      const opened = await establishVaultIntegrityAnchored(account, email, tok, vault);
      integrityRef.current = opened.integrity;
      setToken(tok);
      setItems(opened.items);
      setSendContacts(opened.contacts);
      setPhase("vault");
      if (opened.bootstrapped) toast("Vault integrity protection initialized");
    } catch (error) {
      api.logout(tok).catch(() => {});
      account.lock();
      setAccount(null);
      setToken(null);
      setPhase("unlock");
      throw error;
    }
  }, [account, email, toast]);

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
    let tok: string;
    try {
      tok = await api.login(em, acc.auth_secret);
    } catch (error) {
      acc.lock();
      throw error;
    }
    let vault: VaultData;
    try {
      vault = await api.getVault(tok);
    } catch (error) {
      api.logout(tok).catch(() => {});
      acc.lock();
      throw error;
    }
    let opened: Awaited<ReturnType<typeof establishVaultIntegrity>>;
    try {
      opened = await establishVaultIntegrityAnchored(acc, em, tok, vault);
    } catch (error) {
      api.logout(tok).catch(() => {});
      acc.lock();
      if (error instanceof VaultRollbackError) throw error;
      throw new Error("Encrypted vault integrity check failed. No items were loaded.");
    }
    integrityRef.current = opened.integrity;
    setAccount(acc);
    setEmail(em);
    setToken(tok);
    setItems(opened.items);
    setSendContacts(opened.contacts);
    setPhase("vault");
    if (opened.bootstrapped) toast("Legacy vault verified and integrity protection initialized");
  }, [toast]);

  // ── all vault mutations are serialized manifest + item CAS transactions ──
  const commitVaultOperations = useCallback(
    (operations: VaultOperation[]): Promise<void> => {
      const acc = account;
      const tok = token;
      const epoch = sessionEpoch.current;
      const execute = async (): Promise<void> => {
        try {
          if (!acc || !tok || sessionEpoch.current !== epoch) {
            throw new Error("Vault is locked.");
          }
          const current = integrityRef.current;
          if (!current) throw new Error("Vault integrity state is unavailable.");
          const prepared = prepareVaultMutation(acc, current, operations);
          let result: { revision: number };
          try {
            result = await api.mutateVault(
              tok,
              current.revision,
              prepared.operations,
              prepared.manifest
            );
          } catch (error) {
            const ambiguous =
              error instanceof ApiError && (error.status === 0 || error.status >= 500);
            if (ambiguous && sessionEpoch.current === epoch) {
              try {
                const remote = await api.getVault(tok);
                const reconciled = reconcileVaultMutation(acc, current, prepared, remote);
                if (reconciled && sessionEpoch.current === epoch) {
                  await persistVaultIntegrityAnchor(email, reconciled);
                  if (sessionEpoch.current !== epoch) return;
                  integrityRef.current = reconciled;
                  return;
                }
              } catch {
                // The original mutation is still ambiguous. The outer handler
                // locks before any caller can publish speculative plaintext.
              }
            }
            throw error;
          }
          if (sessionEpoch.current !== epoch) return;
          const completed = completeVaultMutation(
            acc,
            current,
            prepared,
            result.revision
          );
          await persistVaultIntegrityAnchor(email, completed);
          if (sessionEpoch.current !== epoch) return;
          integrityRef.current = completed;
        } catch (error) {
          const mustLock =
            !(error instanceof ApiError) || [0, 401, 409].includes(error.status);
          if (mustLock && sessionEpoch.current === epoch) lock();
          throw error;
        }
      };
      const scheduled = mutationTail.current.then(execute, execute);
      mutationTail.current = scheduled.then(
        () => undefined,
        () => undefined
      );
      return scheduled;
    },
    [account, email, lock, token]
  );

  const persistEncryptedItem = useCallback(
    (id: string, blob: Blob) => commitVaultOperations([{ op: "put", id, blob }]),
    [commitVaultOperations]
  );

  const upsert = useCallback(
    async (item: VaultItem): Promise<boolean> => {
      if (!account || !token) {
        toast("Vault is locked — item was not saved");
        return false;
      }
      const epoch = sessionEpoch.current;
      try {
        const blob = JSON.parse(account.encrypt_item(JSON.stringify(item), item.id)) as Blob;
        await persistEncryptedItem(item.id, blob);
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
        toast(
          sessionEpoch.current !== epoch
            ? "Save was not confirmed — vault locked"
            : "Save failed — item was not changed"
        );
        return false;
      }
    },
    [account, persistEncryptedItem, token, toast]
  );

  const remove = useCallback(
    async (id: string): Promise<boolean> => {
      if (!account || !token) {
        toast("Vault is locked — item was not deleted");
        return false;
      }
      const epoch = sessionEpoch.current;
      try {
        await commitVaultOperations([{ op: "delete", id }]);
        if (sessionEpoch.current !== epoch) return true;
        setItems((prev) => prev.filter((x) => x.id !== id));
        return true;
      } catch {
        toast(
          sessionEpoch.current !== epoch
            ? "Delete was not confirmed — vault locked"
            : "Delete failed — item was not changed"
        );
        return false;
      }
    },
    [account, commitVaultOperations, token, toast]
  );

  // ── bulk import (CSV): expose only items confirmed by the server ──
  const importItems = useCallback(
    async (
      { items: imported }: ImportResult,
      onProgress: ImportProgress = () => {}
    ): Promise<ImportOutcome> => {
      const deduplicated = [...new Map(imported.map((item) => [item.id, item])).values()];
      const requested = deduplicated.length;
      onProgress(0, requested);
      if (requested === 0) return { requested, imported: 0 };
      if (!account || !token) {
        toast("Vault is locked — nothing was imported");
        return { requested, imported: 0 };
      }
      toast(`Importing ${requested} items…`);
      const epoch = sessionEpoch.current;
      const persisted: VaultItem[] = [];
      // The server reserves room for a complete maximum-size manifest plus
      // three maximum-size item blobs. Keep imports within that deterministic
      // transaction envelope instead of estimating ciphertext sizes in JS.
      for (let start = 0; start < deduplicated.length; start += 3) {
        const batch = deduplicated.slice(start, start + 3);
        try {
          const operations: VaultOperation[] = batch.map((item) => ({
            op: "put",
            id: item.id,
            blob: JSON.parse(account.encrypt_item(JSON.stringify(item), item.id)) as Blob,
          }));
          await commitVaultOperations(operations);
          persisted.push(...batch);
          onProgress(persisted.length, requested);
        } catch {
          break;
        }
      }
      const outcome = { requested, imported: persisted.length };
      if (sessionEpoch.current !== epoch) return outcome;
      setItems((prev) => {
        const next = new Map(prev.map((item) => [item.id, item]));
        persisted.forEach((item) => next.set(item.id, item));
        return [...next.values()].sort((a, b) => b.updatedAt - a.updatedAt);
      });
      toast(
        persisted.length === requested
          ? `Imported ${persisted.length} items`
          : `Imported ${persisted.length}/${requested} (remaining items were not added)`
      );
      return outcome;
    },
    [account, commitVaultOperations, token, toast]
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
          persistEncryptedItem={persistEncryptedItem}
          onUpsert={upsert}
          onDelete={remove}
          onImport={importItems}
          onLock={lock}
          toast={toast}
        />
      )}
      {toastMsg && <div className="toast" role="status" aria-live="polite">{toastMsg}</div>}
    </>
  );
}
