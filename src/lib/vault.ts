// Vault store — the front of the encrypted key vault(s) (VISION ④⑤ + the wallet's
// real key ownership). A tiny external store over the Rust vault commands. The app
// now holds MULTIPLE independent wallets side by side (several seeds / private keys
// / Ledgers): create / import / connect adds a wallet; rename / delete manage them.
// Private keys live ONLY in Rust; this layer sees addresses + labels + the one-time
// mnemonic on the backup screen, never a key.
//
// One app password unlocks all software wallets (a Ledger-only setup has none). In
// the plain browser dev-preview there is no Tauri backend, so the actions run
// against an in-memory DEMO store (publicly-known Anvil accounts) so the whole
// onboarding + wallet-management UI is browseable for screenshot testing.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useSyncExternalStore } from "react";
import type { ActivitySwap } from "./activity";
import { isTauri } from "./platform";

export type VaultPhase = "loading" | "absent" | "locked" | "unlocked";

/** Secret kind of an on-disk wallet. A Ledger wallet has no password. */
export type VaultKind = "hd" | "privkey" | "ledger";

/** One wallet for the switcher: id, label, secret kind, and its account addresses. */
export type WalletInfo = {
  id: string;
  label: string;
  kind: VaultKind;
  accounts: string[];
};

export type VaultState = {
  phase: VaultPhase;
  /** An app password is set (some software wallet exists). When false, the only
   *  wallets are Ledgers (no password) — adding a software wallet sets one. */
  hasPassword: boolean;
  /** Every wallet (from memory when unlocked, else on-disk metadata for display). */
  wallets: WalletInfo[];
  /** The active account address (lowercase 0x), or null. */
  active: string | null;
};

/** One Ledger account candidate returned by the device for the picker. */
export type LedgerAccount = { index: number; path: string; address: string };

/** A newly added wallet (id + active address). */
export type WalletRef = { id: string; address: string };

export type TouchIdStatus = {
  available: boolean;
  enabled: boolean;
};

type RustStatus = {
  exists: boolean;
  unlocked: boolean;
  has_password: boolean;
  wallets: WalletInfo[];
  active: string | null;
};
type NewVault = { id: string; address: string; mnemonic: string };
/** A revealed software-wallet secret. Its shape (phrase vs raw key) follows the
 *  caller's already-known `WalletInfo.kind`, so the kind isn't echoed back here. */
export type ExportedSecret = { secret: string };

// Publicly-known Anvil/Hardhat dev addresses — used ONLY for the no-backend
// browser preview. NOT secrets.
const DEMO_ADDRESSES = [
  "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
  "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
  "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc",
  "0x90f79bf6eb2c4f870365e785982e1f101e93b906",
  "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65",
  "0x9965507d1a55bcc2695c58ba16fb37d819b0a4dc",
  "0x976ea74026e726554db657fa54763abd0c3a0aa9",
];
const DEMO_MNEMONIC = "test test test test test test test test test test test junk";
const DEMO_PRIVKEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

let state: VaultState = { phase: "loading", hasPassword: false, wallets: [], active: null };

const listeners = new Set<() => void>();
function set(patch: Partial<VaultState>) {
  state = { ...state, ...patch };
  for (const l of listeners) l();
}
function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useVault(): VaultState {
  return useSyncExternalStore(subscribe, () => state);
}

/** All signer account addresses across every wallet (for the accounts store). */
export function getVaultAccounts(): string[] {
  return state.wallets.flatMap((w) => w.accounts);
}

// ---------------------------------------------------------------------------
// DEMO store (browser preview, no Tauri backend)
// ---------------------------------------------------------------------------
let demoWallets: WalletInfo[] = [];
let demoActive: string | null = null;
let demoHasPassword = false;
let demoLocked = false;
let demoSeq = 0;

function nextDemoAddr(): string {
  const used = new Set(demoWallets.flatMap((w) => w.accounts));
  const free = DEMO_ADDRESSES.find((a) => !used.has(a));
  if (free) return free;
  // Fall back to a synthetic address once the pool is exhausted.
  return `0x${(demoSeq + 1).toString(16).padStart(40, "0")}`;
}
function demoStatus(): VaultState {
  const exists = demoWallets.length > 0;
  return {
    phase: !exists ? "absent" : demoLocked ? "locked" : "unlocked",
    hasPassword: demoHasPassword,
    wallets: demoWallets.map((w) => ({ ...w, accounts: [...w.accounts] })),
    active: demoActive,
  };
}
function demoAddWallet(kind: VaultKind, label = `Wallet ${demoWallets.length + 1}`): WalletRef {
  const id = `demo-${++demoSeq}`;
  const address = nextDemoAddr();
  const walletLabel = label.trim() || `Wallet ${demoWallets.length + 1}`;
  demoWallets.push({ id, label: walletLabel, kind, accounts: [address] });
  if (kind !== "ledger") demoHasPassword = true;
  demoLocked = false;
  demoActive = address;
  return { id, address };
}

/** Load the vault status from the backend (or the demo) on startup. */
export async function refreshVaultStatus(): Promise<void> {
  if (!isTauri()) {
    set(demoStatus());
    return;
  }
  const s = await invoke<RustStatus>("vault_status");
  set({
    phase: !s.exists ? "absent" : s.unlocked ? "unlocked" : "locked",
    hasPassword: s.has_password,
    wallets: s.wallets,
    active: s.active,
  });
}

/** Add a new HD wallet. `password` is required only for the FIRST software wallet
 *  (when no app password is set yet); when already unlocked it's ignored. Returns
 *  the mnemonic for the ONE-TIME backup screen plus the new account address (so the
 *  caller can make it the active selection — keeps shell, backend and dApps in sync). */
export async function createVault(password?: string): Promise<{ mnemonic: string; address: string }> {
  if (!isTauri()) {
    const ref = demoAddWallet("hd");
    set(demoStatus());
    return { mnemonic: DEMO_MNEMONIC, address: ref.address };
  }
  const nv = await invoke<NewVault>("create_vault", { password });
  await refreshVaultStatus();
  return { mnemonic: nv.mnemonic, address: nv.address };
}

/** Add a wallet from a recovery phrase. */
export async function importVault(password: string | undefined, mnemonic: string, name = ""): Promise<WalletRef> {
  if (!isTauri()) {
    const ref = demoAddWallet("hd", name);
    set(demoStatus());
    return ref;
  }
  const ref = await invoke<WalletRef>("import_vault", { password, mnemonic: mnemonic.trim(), label: name.trim() });
  await refreshVaultStatus();
  return ref;
}

/** Add a wallet from a single raw private key. Single-account (no HD derivation). */
export async function importPrivateKey(
  password: string | undefined,
  privateKey: string,
  name = "",
): Promise<WalletRef> {
  const label = name.trim();
  if (!isTauri()) {
    const ref = demoAddWallet("privkey", label);
    set(demoStatus());
    return ref;
  }
  const ref = await invoke<WalletRef>("import_private_key", { password, privateKey: privateKey.trim(), label });
  await refreshVaultStatus();
  return ref;
}

/** Export a software wallet's root secret after password confirmation. HD wallets
 *  return the recovery phrase; imported private-key wallets return the raw key. */
export async function exportWalletSecret(
  walletId: string,
  password: string,
): Promise<ExportedSecret> {
  if (!isTauri()) {
    const w = demoWallets.find((x) => x.id === walletId);
    if (!w) throw new Error("wallet not found");
    if (w.kind === "ledger") throw new Error("Ledger wallets do not have a local secret to export");
    return { secret: w.kind === "hd" ? DEMO_MNEMONIC : DEMO_PRIVKEY };
  }
  return invoke<ExportedSecret>("export_wallet_secret", {
    walletId,
    password,
  });
}

/** List addresses from a connected Ledger (for the picker). Requires the device
 *  unlocked with the Ethereum app open. */
export async function listLedgerAddresses(start: number, count: number): Promise<LedgerAccount[]> {
  if (!isTauri()) {
    // Browser preview: synthesize a deterministic picker (enough rows for
    // pagination) by varying a demo address's tail with the derivation index.
    return Array.from({ length: count }, (_, i) => {
      const index = start + i;
      const base = DEMO_ADDRESSES[index % DEMO_ADDRESSES.length].slice(2);
      const suffix = index.toString(16).padStart(4, "0");
      const address = "0x" + (base.slice(0, 36) + suffix).slice(0, 40);
      return { index, path: `m/44'/60'/${index}'/0/0`, address };
    });
  }
  return invoke<LedgerAccount[]>("ledger_addresses", { start, count });
}

/** Add a Ledger account at `path` as a new wallet (no password). */
export async function connectLedger(path: string, name = ""): Promise<WalletRef> {
  if (!isTauri()) {
    const ref = demoAddWallet("ledger", name);
    set(demoStatus());
    return ref;
  }
  const ref = await invoke<WalletRef>("connect_ledger", { path, label: name.trim() });
  await refreshVaultStatus();
  return ref;
}

/** Transaction shape the wallet's own Send hands to the backend. */
export type SendTx = {
  to: string;
  value?: string;
  data?: string;
  activity?: {
    kind?: "send" | "contract" | "token_send" | "swap";
    counterparty?: string;
    assetSymbol?: string;
    assetDecimals?: number;
    amount?: string;
    tokenAddress?: string;
    swap?: ActivitySwap;
  };
};

/**
 * How far a signing request has got. The backend reports each step so the UI can
 * name what it is actually waiting for — telling the user to "confirm in window"
 * while no window exists yet is how a stalled send looked like a frozen app.
 */
export type RequestPhase =
  | "preparing"
  | "awaiting-window"
  | "awaiting-approval"
  | "broadcasting";

/**
 * Subscribe to request-phase updates; returns an unsubscribe function. The stream
 * covers every signing request, dApp ones included — a caller that only has its
 * own send on screen (the Send modal) can take them all, since nothing else is
 * showing a phase at the same time.
 */
export function onRequestPhase(cb: (phase: RequestPhase) => void): () => void {
  if (!isTauri()) return () => {};
  const stop = listen<{ id: string | null; phase: RequestPhase }>(
    "wallet-request-phase",
    (e) => cb(e.payload.phase),
  );
  return () => void stop.then((un) => un());
}

/**
 * Wallet-initiated send. Runs through the SAME approval window + signing path as a
 * dApp's eth_sendTransaction, so the user confirms (and can tune the fee) there.
 * Returns the broadcast tx hash. In the browser preview there's no signer, so it
 * just simulates a broadcast.
 */
export async function walletSend(chainId: string, tx: SendTx): Promise<string> {
  if (!isTauri()) {
    await new Promise((r) => setTimeout(r, 700));
    return "0x" + "ad".repeat(32); // demo: fake but well-formed tx hash
  }
  return invoke<string>("wallet_send", { chainId, tx });
}

/** Unlock every wallet with the app password. Throws "incorrect password" on a bad one. */
export async function unlockVault(password: string): Promise<void> {
  if (!isTauri()) {
    demoLocked = false;
    set(demoStatus());
    return;
  }
  await invoke<string>("unlock_vault", { password });
  await refreshVaultStatus();
}

/** Whether this Mac can offer Touch ID and whether this vault opted in. */
export async function getTouchIdStatus(): Promise<TouchIdStatus> {
  if (!isTauri()) return { available: false, enabled: false };
  return invoke<TouchIdStatus>("touch_id_status");
}

/** Verify Touch ID, then save the current in-memory vault password in Keychain. */
export async function enableTouchId(reason: string): Promise<void> {
  if (!isTauri()) throw new Error("Touch ID is only available in the macOS app");
  await invoke("enable_touch_id", { reason });
}

/** Remove the local Keychain item and its non-secret enabled marker. */
export async function disableTouchId(): Promise<void> {
  if (!isTauri()) throw new Error("Touch ID is only available in the macOS app");
  await invoke("disable_touch_id");
}

/** Ask macOS for Touch ID, then read the password from Keychain and unlock. */
export async function unlockVaultWithTouchId(reason: string): Promise<void> {
  if (!isTauri()) throw new Error("Touch ID is only available in the macOS app");
  await invoke<string>("unlock_vault_with_touch_id", { reason });
  await refreshVaultStatus();
}

/** Lock all wallets (drop keys + password from memory). */
export async function lockVault(): Promise<void> {
  if (isTauri()) {
    await invoke("lock_vault");
    await refreshVaultStatus();
    return;
  }
  demoLocked = true;
  set(demoStatus());
}

/** Reset EVERYTHING: delete every keystore and return to onboarding. The
 *  "forgot password" escape hatch — IRREVERSIBLE; the caller must confirm first. */
export async function resetVault(): Promise<void> {
  if (isTauri()) {
    await invoke("reset_vault");
    await refreshVaultStatus();
    return;
  }
  demoWallets = [];
  demoActive = null;
  demoHasPassword = false;
  demoLocked = false;
  set(demoStatus());
}

/** Switch the active account by ADDRESS (across all wallets); pushes accountsChanged
 *  to dApps backend-side. */
export async function selectAccount(address: string): Promise<void> {
  if (!isTauri()) {
    demoActive = address;
    set(demoStatus());
    return;
  }
  await invoke<string>("select_account", { address });
  set({ active: address });
}

/** Expose a public watch-only address to dApps. This does not switch the backend
 *  signing key, so write/sign requests still require a real signer account. */
export async function exposeDappAccount(address: string): Promise<void> {
  if (!isTauri()) return;
  await invoke<string>("expose_dapp_account", { address });
}

/** Derive + persist the next HD account in wallet `walletId`. Returns its address. */
export async function addVaultAccount(walletId: string): Promise<string> {
  if (!isTauri()) {
    const w = demoWallets.find((x) => x.id === walletId);
    if (!w) throw new Error("wallet not found");
    if (w.kind !== "hd") throw new Error("this wallet can't derive more accounts");
    const next = nextDemoAddr();
    w.accounts = [...w.accounts, next];
    demoActive = next;
    set(demoStatus());
    return next;
  }
  const address = await invoke<string>("add_account", { walletId });
  await refreshVaultStatus();
  return address;
}

/** Rename a wallet (plaintext label only — no password). */
export async function renameWallet(id: string, label: string): Promise<void> {
  if (!isTauri()) {
    const w = demoWallets.find((x) => x.id === id);
    if (w) w.label = label.trim() || w.label;
    set(demoStatus());
    return;
  }
  await invoke("rename_wallet", { id, label });
  await refreshVaultStatus();
}

/** Delete a single wallet (its keystore). IRREVERSIBLE for a software wallet —
 *  the caller must confirm first. */
export async function deleteWallet(id: string): Promise<void> {
  if (!isTauri()) {
    demoWallets = demoWallets.filter((w) => w.id !== id);
    if (!demoWallets.flatMap((w) => w.accounts).includes(demoActive ?? "")) {
      demoActive = demoWallets.flatMap((w) => w.accounts)[0] ?? null;
    }
    if (demoWallets.length === 0) demoHasPassword = false;
    set(demoStatus());
    return;
  }
  await invoke("delete_wallet", { id });
  await refreshVaultStatus();
}
