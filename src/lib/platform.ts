// Platform bridge for the embedded dApp browser (VISION feature ③).
//
// Each open dApp tab is its own NATIVE child webview (Rust-side, with
// window.ethereum injected), labeled `dapp-<id>`, that the shell positions over
// the `.browser-content` rect via these commands. In the plain browser dev-preview
// there is no native webview, so isTauri() is false and BrowserView falls back to
// an <iframe>.

import { invoke } from "@tauri-apps/api/core";
import { createSerialQueue } from "./serialQueue";

export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export type Rect = { x: number; y: number; w: number; h: number };

/** Webview label for a tab. Must match the `dapp-<id>` shape the Rust label
 *  guard enforces (capabilities/dapp.json scopes `dapp-*`). */
export function dappLabel(tabId: string): string {
  return `dapp-${tabId.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
}

/** Create-or-show the tab webview over `rect`. Navigates to `url` only on first
 *  creation, so switching back to a tab preserves its page. */
export function openDapp(
  label: string,
  url: string,
  rect: Rect,
): Promise<void> {
  return invoke("open_dapp", { label, url, ...rect });
}

/** Track the content rect across window/layout resizes. */
export function setDappBounds(label: string, rect: Rect): Promise<void> {
  return invoke("set_dapp_bounds", { label, ...rect });
}

// The overlay sync commands are async on the Rust side, so concurrent invokes
// can complete out of order — a slow `show` finishing after a fast `hide`
// leaves the transparent overlay stuck on top of the whole window, eating all
// input. One serial queue per overlay keeps state requests in issue order.
const toastOverlayQueue = createSerialQueue();
const menuOverlayQueue = createSerialQueue();

/** Show or hide the native toast overlay that sits above dApp child webviews. */
export function syncToastOverlay(rect: Rect | null): Promise<void> {
  return toastOverlayQueue(() =>
    invoke("sync_toast_overlay", rect ? { visible: true, ...rect } : { visible: false }),
  );
}

/** Show or hide the native dropdown-menu overlay (full-window, above dApp
 *  child webviews — see lib/menuOverlay.ts). */
export function syncMenuOverlay(rect: Rect | null): Promise<void> {
  return menuOverlayQueue(() =>
    invoke("sync_menu_overlay", rect ? { visible: true, ...rect } : { visible: false }),
  );
}

export function resolveDappDialog(
  id: string,
  action: "ok" | "cancel",
  value?: string | null,
): Promise<void> {
  return invoke("resolve_dapp_dialog", { id, action, value });
}

/** Reload the native dApp tab webview. */
export function reloadDapp(label: string): Promise<void> {
  return invoke("reload_dapp", { label });
}

/** Navigate an existing tab without replacing its webview or wallet provider. */
export function navigateDapp(label: string, url: string): Promise<void> {
  return invoke("navigate_dapp", { label, url });
}

/** Navigate back inside the native dApp tab webview. When the page has no
 * history entry, the webview stays on the current page. */
export function goBackDapp(label: string): Promise<void> {
  return invoke("go_back_dapp", { label });
}

/** Show a tab webview whose page never reported a finished load — the loading
 *  timeout's escape hatch (`open_dapp` keeps an unloaded webview hidden so it
 *  cannot cover the loading animation with a blank rectangle). */
export function showDapp(label: string): Promise<void> {
  return invoke("show_dapp", { label });
}

/** Hide a tab webview (switch to another tab / Wallet / dApps). */
export function hideDapp(label: string): Promise<void> {
  return invoke("hide_dapp", { label });
}

/** Close (destroy) a tab webview when its tab is closed. */
export function closeDapp(label: string): Promise<void> {
  return invoke("close_dapp", { label });
}

export async function openExternalUrl(url: string): Promise<void> {
  if (!isTauri()) {
    window.open(url, "_blank", "noopener,noreferrer");
    return;
  }
  await invoke("open_external_url", { url });
}

/** Viewport-relative rect of an element = its position within the window, since
 *  the trusted shell webview fills the window at (0,0). */
export function rectOf(el: HTMLElement): Rect {
  const r = el.getBoundingClientRect();
  return { x: r.left, y: r.top, w: r.width, h: r.height };
}
