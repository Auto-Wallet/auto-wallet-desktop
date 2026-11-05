// Chain registry — now backend-owned (VISION ⑥: manage Chains). The Rust side
// (src-tauri/src/lib.rs `chains_state`) is the source of truth: built-in chains
// plus any user-added networks / RPC overrides, persisted to chains.json. This
// store mirrors it for the UI and exposes add/edit/remove. In the browser preview
// (no Tauri) it falls back to the in-memory built-ins.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { useSyncExternalStore } from "react";
import { isTauri } from "./platform";
import { SUPPORTED_CHAINS } from "./tokenData";

export type Chain = {
  /** EIP-155 chain id as a 0x-hex string (what dApps see via eth_chainId). */
  id: string;
  name: string;
  /** Native gas-token symbol shown in the Wallet page. */
  symbol: string;
  rpc: string;
  /** Native token decimals (usually 18). */
  decimals: number;
  /** Brand color for the chain dot/badge. */
  color: string;
  /** Block explorer transaction URL base, e.g. https://etherscan.io/tx/. */
  explorerUrl?: string;
  /** Ships with the app. Built-in and user chains can both be edited and removed. */
  builtin: boolean;
};

// Browser-preview fallback only — in the Tauri app the registry comes from the
// Rust `get_chains`. Kept in sync with `builtin_chains()` in src-tauri/src/lib.rs.
export const BUILTIN_CHAINS: Chain[] = [
  { id: "0x1",     name: "Ethereum",      symbol: "ETH",   rpc: "https://ethereum-rpc.publicnode.com",            decimals: 18, color: "#627EEA", builtin: true },
  { id: "0x2105",  name: "Base",          symbol: "ETH",   rpc: "https://base-rpc.publicnode.com",                decimals: 18, color: "#0052FF", builtin: true },
  { id: "0xa",     name: "OP Mainnet",    symbol: "ETH",   rpc: "https://optimism-rpc.publicnode.com",            decimals: 18, color: "#FF0420", builtin: true },
  { id: "0xa4b1",  name: "Arbitrum One",  symbol: "ETH",   rpc: "https://arbitrum-one-rpc.publicnode.com",        decimals: 18, color: "#28A0F0", builtin: true },
  { id: "0x89",    name: "Polygon",       symbol: "POL",   rpc: "https://polygon-bor-rpc.publicnode.com",         decimals: 18, color: "#8247E5", builtin: true },
  { id: "0x38",    name: "BNB Chain",     symbol: "BNB",   rpc: "https://bsc-dataseed.bnbchain.org",              decimals: 18, color: "#F3BA2F", builtin: true },
  { id: "0xa86a",  name: "Avalanche",     symbol: "AVAX",  rpc: "https://avalanche-c-chain-rpc.publicnode.com",   decimals: 18, color: "#E84142", builtin: true },
  { id: "0xe708",  name: "Linea",         symbol: "ETH",   rpc: "https://linea-rpc.publicnode.com",               decimals: 18, color: "#61DFFF", builtin: true },
  { id: "0x13e31", name: "Blast",         symbol: "ETH",   rpc: "https://blast-rpc.publicnode.com",               decimals: 18, color: "#FCD000", builtin: true },
  { id: "0x144",   name: "zkSync Era",    symbol: "ETH",   rpc: "https://mainnet.era.zksync.io",                  decimals: 18, color: "#8C8DFC", builtin: true },
  { id: "0x44d",   name: "Polygon zkEVM", symbol: "ETH",   rpc: "https://zkevm-rpc.com",                          decimals: 18, color: "#7B3FE4", builtin: true },
  { id: "0x92",    name: "Sonic",         symbol: "S",     rpc: "https://rpc.soniclabs.com",                      decimals: 18, color: "#1969FF", builtin: true },
  { id: "0xc4",    name: "X Layer",       symbol: "OKB",   rpc: "https://rpc.xlayer.tech",                        decimals: 18, color: "#1A1A1A", builtin: true },
  { id: "0x1e0",   name: "World Chain",   symbol: "ETH",   rpc: "https://worldchain-mainnet.g.alchemy.com/public", decimals: 18, color: "#1A1A1A", builtin: true },
  { id: "0x250",   name: "Astar",         symbol: "ASTR",  rpc: "https://evm.astar.network",                      decimals: 18, color: "#1B6DC1", builtin: true },
  { id: "0x378",   name: "Wanchain",      symbol: "WAN",   rpc: "https://gwan-ssl.wandevs.org:56891",             decimals: 18, color: "#2A6BE9", builtin: true },
  { id: "0x440",   name: "Metis",         symbol: "METIS", rpc: "https://andromeda.metis.io/?owner=1088",         decimals: 18, color: "#00DACC", builtin: true },
  { id: "0xa4ec",  name: "Celo",          symbol: "CELO",  rpc: "https://forno.celo.org",                         decimals: 18, color: "#FCB728", builtin: true },
];

// chainId (lowercased) -> remote brand-logo URL, from the baked xflows snapshot
// (src/lib/tokenData.ts). The chain registry itself is backend-owned and carries
// no logo; the UI joins this in at render time so the native coin shows the same
// kind of icon a token does. User-added chains aren't in the snapshot -> undefined,
// and the Coin glyph falls back to its brand color.
const CHAIN_LOGO: Record<string, string> = {};
for (const c of SUPPORTED_CHAINS) if (c.logo) CHAIN_LOGO[c.id.toLowerCase()] = c.logo;

/** Remote brand logo for a chain id, or undefined (built-ins only). */
export function chainLogo(id: string): string | undefined {
  return CHAIN_LOGO[id.toLowerCase()];
}

let chains: Chain[] = BUILTIN_CHAINS;
const listeners = new Set<() => void>();
function emit() {
  for (const l of listeners) l();
}
function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useChains(): Chain[] {
  return useSyncExternalStore(subscribe, () => chains);
}

/** Non-reactive read of the current chain list. */
export function getChains(): Chain[] {
  return chains;
}

export function findChain(id: string): Chain | undefined {
  const want = id.toLowerCase();
  return chains.find((c) => c.id.toLowerCase() === want);
}

/** Load the effective chain registry from the backend (or fall back to built-ins). */
export async function loadChains(): Promise<void> {
  if (!isTauri()) {
    chains = BUILTIN_CHAINS;
    emit();
    return;
  }
  chains = await invoke<Chain[]>("get_chains");
  emit();
  // A dApp can add a network via wallet_addEthereumChain — refresh the list when the
  // backend signals it (registered once).
  if (!chainsListenerBound) {
    chainsListenerBound = true;
    void listen("chains-changed", () => void loadChains());
  }
}
let chainsListenerBound = false;

export async function addChain(chain: Omit<Chain, "builtin">): Promise<void> {
  const next: Chain = { ...chain, builtin: false };
  if (!isTauri()) {
    chains = [...chains, next];
    emit();
    return;
  }
  chains = await invoke<Chain[]>("add_chain", { chain: next });
  emit();
}

export async function updateChain(chain: Chain): Promise<void> {
  if (!isTauri()) {
    chains = chains.map((c) => (c.id.toLowerCase() === chain.id.toLowerCase() ? { ...chain } : c));
    emit();
    return;
  }
  chains = await invoke<Chain[]>("update_chain", { chain });
  emit();
}

export async function removeChain(id: string): Promise<void> {
  if (!isTauri()) {
    chains = chains.filter((c) => c.id.toLowerCase() !== id.toLowerCase());
    emit();
    return;
  }
  chains = await invoke<Chain[]>("remove_chain", { id });
  emit();
}
