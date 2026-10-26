import "./BrowserView.css";
import { BrowserUrlInput } from "./BrowserUrlInput";
import { useEffect, useMemo, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useChains, type Chain } from "../lib/chains";
import { shortAddress } from "../lib/format";
import { setActive, useAccounts, useActiveAccount } from "../lib/accounts";
import { setActiveChain, useActiveChain } from "../lib/activeChain";
import { useT } from "../lib/i18n";
import { Icon } from "../lib/icons";
import { Avatar, CopyButton, DappIcon } from "../lib/ui";
import { toast } from "../lib/toast";
import { ChainIcon } from "../lib/ChainIcon";
import { filterChains } from "../lib/chainSearch";
import { useDropdown } from "../lib/transitions";
import { hostOf, type Dapp } from "../lib/dapps";
import { hasDappLoaded, markDappLoaded } from "../lib/dappLoadState";
import {
  dappLabel,
  goBackDapp,
  hideDapp,
  isTauri,
  navigateDapp,
  openDapp,
  rectOf,
  reloadDapp,
  setDappBounds,
  showDapp,
} from "../lib/platform";
import {
  menuAnchorFor,
  useMenuOverlay,
  type MenuAnchor,
  type MenuOverlayPayload,
} from "../lib/menuOverlay";

export type Tab = { id: string; dapp: Dapp };

function reportDappControlError(action: string, label: string, error: unknown) {
  console.error(`[AutoDesktop] ${action} failed for ${label}`, error);
}

// The chrome around one open dApp tab (VISION feature ③), restyled to Aurora:
// top bar with back/reload, the URL, the active chain + account chips, content
// below. Each tab is a persistent native `dapp-<id>` child webview (Rust-side,
// window.ethereum injected) that the shell shows over `.browser-content`;
// switching tabs hides one and shows another without reloading. In the browser
// preview we stand it in with an <iframe>. The native-webview positioning logic
// is unchanged — only the surrounding chrome was redesigned.
export default function BrowserView({ tab, onBack }: { tab: Tab; onBack: () => void }) {
  const { dapp } = tab;
  const { t } = useT();
  const label = dappLabel(tab.id);
  const chainId = useActiveChain();
  const chains = useChains();
  const chain = chains.find((c) => c.id === chainId) ?? chains[0];
  const contentRef = useRef<HTMLDivElement>(null);
  const native = isTauri();

  const [focus, setFocus] = useState(false);
  const [currentUrl, setCurrentUrl] = useState(dapp.url);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [reloading, setReloading] = useState(false);
  const [dappLoading, setDappLoading] = useState(() => !hasDappLoaded(label));

  useEffect(() => {
    setCurrentUrl(dapp.url);
    setDappLoading(!hasDappLoaded(label));
  }, [dapp.url, label]);

  useEffect(() => {
    if (!native) return;
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<{ label: string; url: string }>("dapp-navigated", (event) => {
      if (event.payload?.label !== label) return;
      setCurrentUrl(event.payload.url);
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [native, label]);

  useEffect(() => {
    if (!native) return;
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<{ label: string; url: string }>("dapp-load-finished", (event) => {
      if (event.payload?.label !== label) return;
      markDappLoaded(label);
      setCurrentUrl(event.payload.url);
      setDappLoading(false);

      const el = contentRef.current;
      if (el) {
        void openDapp(label, event.payload.url, rectOf(el)).catch((e) =>
          reportDappControlError("open_dapp after load", label, e),
        );
      }
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [native, label]);

  useEffect(() => {
    if (!native || !dappLoading) return undefined;
    const timer = window.setTimeout(() => {
      const el = contentRef.current;
      if (el) {
        void openDapp(label, currentUrl, rectOf(el)).catch((e) =>
          reportDappControlError("open_dapp fallback", label, e),
        );
      }
      // The page never reported a finished load; show whatever it has rather
      // than leave the user behind the animation forever.
      void showDapp(label).catch((e) => reportDappControlError("show_dapp fallback", label, e));
      setDappLoading(false);
    }, 20_000);
    return () => window.clearTimeout(timer);
  }, [native, dappLoading, label, currentUrl]);

  // Show this tab's native webview over the content rect, track resizes, and hide
  // it (NOT close — the tab persists) when this view unmounts/switches away.
  useEffect(() => {
    if (!native) return;
    const el = contentRef.current;
    if (!el) return;

    void openDapp(label, dapp.url, rectOf(el)).catch((e) =>
      reportDappControlError("open_dapp", label, e),
    );

    const sync = () =>
      void setDappBounds(label, rectOf(el)).catch((e) =>
        reportDappControlError("set_dapp_bounds", label, e),
      );
    const syncAfterLayoutSettles = () => {
      sync();
      requestAnimationFrame(() => {
        sync();
        requestAnimationFrame(sync);
      });
      window.setTimeout(sync, 80);
      window.setTimeout(sync, 250);
    };
    const ro = new ResizeObserver(sync);
    ro.observe(el);
    window.addEventListener("resize", sync);
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<{ label: string }>("dapp-layout-invalidated", (event) => {
      if (event.payload.label !== label) return;
      syncAfterLayoutSettles();
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });

    return () => {
      disposed = true;
      unlisten?.();
      ro.disconnect();
      window.removeEventListener("resize", sync);
      void hideDapp(label).catch((e) => reportDappControlError("hide_dapp", label, e));
    };
  }, [native, label, dapp.url]);

  async function handleReload() {
    if (reloading) return;
    setReloading(true);
    setDappLoading(true);
    try {
      if (native) {
        await reloadDapp(label);
      } else {
        setReloadNonce((n) => n + 1);
      }
      window.setTimeout(() => setReloading(false), 800);
    } catch {
      setReloading(false);
    }
  }

  function handleBack() {
    if (!native) {
      onBack();
      return;
    }
    void goBackDapp(label).catch((e) => reportDappControlError("go_back_dapp", label, e));
  }

  async function handleNavigate(target: string) {
    setDappLoading(true);
    if (native) {
      await navigateDapp(label, target);
    } else {
      setReloadNonce((n) => n + 1);
    }
    setCurrentUrl(target);
  }

  return (
    <div className="browser">
      <header className="browser-bar">
        <button className="icon-btn" onClick={handleBack} title={t("browser.back")}>
          <Icon name="arrowLeft" size={18} />
        </button>
        <button
          className={`icon-btn browser-reload${reloading ? " loading" : ""}`}
          onClick={() => void handleReload()}
          title={t("browser.reload")}
          disabled={reloading}
        >
          <Icon name="refresh" size={17} />
        </button>

        <div className={`url-bar${focus ? " focus" : ""}`}>
          <span className="lock-ic">
            <Icon name="lock" size={14} />
          </span>
          <DappIcon
            className="url-fav"
            url={currentUrl}
            name={dapp.name}
            refreshAt={dapp.iconRefreshAt}
            size={18}
            radius={5}
          />
          <BrowserUrlInput
            currentUrl={currentUrl}
            onFocusChange={setFocus}
            onNavigate={handleNavigate}
            onError={(error) => {
              setDappLoading(false);
              reportDappControlError("navigate_dapp", label, error);
              toast(t("browser.navigationFailed"), "warn");
            }}
          />
          <Icon name="external" size={15} />
        </div>

        <div className="browser-chips">
          <ChainChip chain={chain} chains={chains} />
          <AcctChip />
        </div>
      </header>

      <section className="browser-content" ref={contentRef}>
        {dappLoading && (
          <DappLoadingOverlay dapp={dapp} label={t("browser.loadingDapp")} />
        )}
        {native ? (
          <div className="native-placeholder" />
        ) : (
          <>
            <iframe
              key={reloadNonce}
              className="dapp-frame"
              src={currentUrl}
              title={dapp.name}
              onLoad={() => {
                markDappLoaded(label);
                setDappLoading(false);
                setReloading(false);
              }}
            />
            <div className="frame-note">
              <Icon name="shieldCheck" size={15} /> In the desktop app, <b>{hostOf(currentUrl)}</b> loads in a
              native webview with <code>window.ethereum</code> injected.
            </div>
          </>
        )}
      </section>
    </div>
  );
}

function DappLoadingOverlay({ dapp, label }: { dapp: Dapp; label: string }) {
  const host = hostOf(dapp.url);
  return (
    <div className="dapp-loading" role="status" aria-live="polite">
      <div className="dapp-loading-orbit">
        <span />
        <DappIcon
          url={dapp.url}
          name={dapp.name}
          refreshAt={dapp.iconRefreshAt}
          size={34}
          radius={10}
        />
      </div>
      <div className="dapp-loading-title">{label}</div>
      <div className="dapp-loading-sub">
        {dapp.name} · {host}
      </div>
      <div className="dapp-loading-bar">
        <i />
      </div>
    </div>
  );
}

// The account chip in the dApp top bar IS a wallet switcher: picking an account
// runs setActive → selectAccount, which switches the backend's active signer and
// pushes accountsChanged into this dApp, so the page follows the new address.
// In the native app the dropdown renders in the menu-overlay child webview
// (lib/menuOverlay.ts) — an in-shell dropdown would be covered by the dApp
// webview; the in-shell DOM menu below remains for the browser preview.
function AcctChip() {
  const { t } = useT();
  const accounts = useAccounts();
  const active = useActiveAccount();
  const native = isTauri();
  const [open, setOpen] = useState(false);
  const menu = useDropdown(open);
  const [anchor, setAnchor] = useState<MenuAnchor | null>(null);
  const isActive = (addr: string) => addr.toLowerCase() === active.address.toLowerCase();
  const payload = useMemo<MenuOverlayPayload | null>(
    () =>
      anchor
        ? {
            kind: "account",
            anchor,
            accounts: accounts.map((a) => ({ address: a.address, label: a.label })),
            activeAddress: active.address,
            copyTitle: t("wallet.copy"),
          }
        : null,
    [anchor, accounts, active.address, t],
  );
  useMenuOverlay(payload, (action) => {
    if (action.type === "copy-result") {
      toast(t(action.success ? "common.copied" : "common.copyFailed"), action.success ? "ok" : "warn");
      return;
    }
    if (action.type === "select-account") setActive(action.address);
    setAnchor(null);
  });
  return (
    <div className="chain-wrap">
      <button
        className="acct-chip"
        onClick={(e) => {
          if (!native) return setOpen((o) => !o);
          const next = menuAnchorFor(e.currentTarget);
          setAnchor((a) => (a ? null : next));
        }}
        title={t("wallet.switchAccount")}
      >
        <Avatar address={active.address} size={24} />
        <span className="mono">{shortAddress(active.address, 5, 4)}</span>
        <Icon name="chevronD" size={14} />
      </button>
      {menu.mounted && (
        <>
          <div style={{ position: "fixed", inset: 0, zIndex: 30 }} onClick={() => setOpen(false)} />
          <div
            className={`chain-menu acct-pop scroll t-dropdown ${menu.cls}`}
            data-origin="top-right"
          >
            {accounts.map((a) => (
              <div
                key={a.address}
                role="button"
                tabIndex={0}
                className={`acct-opt${isActive(a.address) ? " on" : ""}`}
                onClick={() => {
                  setActive(a.address);
                  setOpen(false);
                }}
                onKeyDown={(e) => {
                  if (e.key !== "Enter" && e.key !== " ") return;
                  e.preventDefault();
                  setActive(a.address);
                  setOpen(false);
                }}
              >
                <Avatar address={a.address} size={28} />
                <span className="meta">
                  <span className="l">{a.label}</span>
                  <span className="a">{shortAddress(a.address, 8, 6)}</span>
                </span>
                <CopyButton
                  className="acct-copy"
                  title={t("wallet.copy")}
                  size={14}
                  value={a.address}
                  onCopied={() => toast(t("common.copied"))}
                />
                {isActive(a.address) && (
                  <span className="check">
                    <Icon name="check" size={15} />
                  </span>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

// Same native-vs-preview split as AcctChip: native renders in the menu overlay.
function ChainChip({ chain, chains }: { chain: Chain; chains: Chain[] }) {
  const { t } = useT();
  const native = isTauri();
  const [open, setOpen] = useState(false);
  const menu = useDropdown(open);
  const [query, setQuery] = useState("");
  const [anchor, setAnchor] = useState<MenuAnchor | null>(null);
  const filteredChains = useMemo(() => filterChains(chains, query), [chains, query]);
  const payload = useMemo<MenuOverlayPayload | null>(
    () =>
      anchor
        ? {
            kind: "chain",
            anchor,
            chains: chains.map((c) => ({ id: c.id, name: c.name, symbol: c.symbol, color: c.color })),
            activeChainId: chain.id,
          }
        : null,
    [anchor, chains, chain.id],
  );
  useMenuOverlay(payload, (action) => {
    if (action.type === "select-chain") void setActiveChain(action.id);
    setAnchor(null);
  });
  return (
    <div className="chain-wrap">
      <button
        className="chain-chip"
        onClick={(e) => {
          if (!native) {
            setQuery("");
            return setOpen((o) => !o);
          }
          const next = menuAnchorFor(e.currentTarget);
          setAnchor((a) => (a ? null : next));
        }}
      >
        <ChainIcon chain={chain} size={16} />
        {chain.name}
        <Icon name="chevronD" size={14} />
      </button>
      {menu.mounted && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 30 }}
            onClick={() => {
              setOpen(false);
              setQuery("");
            }}
          />
          <div
            className={`chain-menu chain-picker t-dropdown ${menu.cls}`}
            data-origin="top-right"
          >
            <label className="chain-search">
              <Icon name="search" size={15} />
              <input
                value={query}
                autoFocus
                aria-label={t("browser.searchNetworks")}
                placeholder={t("browser.searchNetworks")}
                onChange={(event) => setQuery(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key !== "Escape") return;
                  setOpen(false);
                  setQuery("");
                }}
              />
            </label>
            <div className="chain-list scroll">
              {filteredChains.map((c) => (
                <button
                  key={c.id}
                  className={`chain-opt${c.id === chain.id ? " on" : ""}`}
                  onClick={() => {
                    void setActiveChain(c.id);
                    setOpen(false);
                    setQuery("");
                  }}
                >
                  <ChainIcon chain={c} size={20} />
                  <span className="nm">{c.name}</span>
                  {c.id === chain.id && (
                    <span className="check">
                      <Icon name="check" size={16} />
                    </span>
                  )}
                </button>
              ))}
              {filteredChains.length === 0 && (
                <div className="chain-empty">{t("browser.noNetworkMatches")}</div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
