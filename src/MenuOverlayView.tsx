import { useEffect, useMemo, useState } from "react";
import {
  MENU_OVERLAY_CHANNEL,
  MENU_OVERLAY_KEY,
  type MenuOverlayAction,
  type MenuOverlayPayload,
} from "./lib/menuOverlay";
import { BrowserAccountMenu } from "./pages/BrowserAccountMenu";
import { Icon } from "./lib/icons";
import { ChainIcon } from "./lib/ChainIcon";
import { filterChains } from "./lib/chainSearch";
import { useT } from "./lib/i18n";
import { useEnterExit } from "./lib/transitions";

// The interactive twin of ToastOverlayView: renders the browser top-bar dropdown
// menus (account / chain switcher) inside the transparent full-window
// `menu-overlay` child webview, which native stacking puts above the dApp
// webview — BrowserView's in-shell dropdowns would be covered by the page.
// Wallet/menu actions are posted back to the shell over BroadcastChannel.
// Copy buttons write the native clipboard here and report the result there.

function post(action: MenuOverlayAction) {
  const channel = new BroadcastChannel(MENU_OVERLAY_CHANNEL);
  channel.postMessage({ action });
  window.setTimeout(() => channel.close(), 80);
}

export default function MenuOverlayView() {
  const [menu, setMenu] = useState<MenuOverlayPayload | null>(null);
  // The shell tears this webview down to dismiss the menu, so only the open
  // half of the dropdown transition ever runs here.
  const { cls: openCls } = useEnterExit(!!menu, 0);

  useEffect(() => {
    document.body.classList.add("menu-overlay-body");
    const saved = localStorage.getItem(MENU_OVERLAY_KEY);
    if (saved) {
      try {
        setMenu(JSON.parse(saved));
      } catch {
        // Ignore stale payloads; the shell broadcasts the live state right after.
      }
    }
    const channel = new BroadcastChannel(MENU_OVERLAY_CHANNEL);
    channel.onmessage = (event) => {
      if (event.data && "state" in event.data) setMenu(event.data.state);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      if (menu?.kind === "dialog") {
        post({ type: "resolve-dapp-dialog", id: menu.id, action: "cancel" });
      } else {
        post({ type: "dismiss" });
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      channel.close();
      document.body.classList.remove("menu-overlay-body");
    };
  }, [menu]);

  if (!menu) return null;

  if (menu.kind === "dialog") {
    return (
      <div className="menu-overlay-root dialog">
        <DappDialog dialog={menu} />
      </div>
    );
  }

  return (
    <div className="menu-overlay-root" onMouseDown={() => post({ type: "dismiss" })}>
      <div
        data-origin="top-right"
        className={`chain-menu menu-overlay-menu t-dropdown ${openCls}${menu.kind === "account" ? " acct-pop" : " chain-picker"}`}
        style={{
          top: menu.anchor.top,
          right: menu.anchor.right,
          maxHeight: menu.kind === "chain"
            ? `calc(100vh - ${menu.anchor.top + 12}px)`
            : `min(380px, calc(100vh - ${menu.anchor.top + 12}px))`,
        }}
        onMouseDown={(e) => e.stopPropagation()}
      >
        {menu.kind === "account" ? <AcctMenu menu={menu} /> : <ChainMenu menu={menu} />}
      </div>
    </div>
  );
}

function DappDialog({ dialog }: { dialog: Extract<MenuOverlayPayload, { kind: "dialog" }> }) {
  const [value, setValue] = useState(dialog.defaultValue ?? "");
  const isPrompt = dialog.dialogKind === "prompt";
  const showCancel = dialog.dialogKind === "confirm" || dialog.dialogKind === "prompt";

  return (
    <div className="dapp-dialog-card" role="dialog" aria-modal="true" onMouseDown={(e) => e.stopPropagation()}>
      <div className="dapp-dialog-head">
        <span className="dapp-dialog-icon">
          <Icon name="alert" size={18} />
        </span>
        <div>
          <div className="dapp-dialog-title">{dialog.labels.title}</div>
          <div className="dapp-dialog-origin">{dialog.origin}</div>
        </div>
      </div>
      <div className="dapp-dialog-message">{dialog.message || "\u00a0"}</div>
      {isPrompt && (
        <input
          className="input"
          value={value}
          autoFocus
          placeholder={dialog.labels.promptPlaceholder}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => {
            if (e.key !== "Enter") return;
            post({ type: "resolve-dapp-dialog", id: dialog.id, action: "ok", value });
          }}
        />
      )}
      <div className="dapp-dialog-actions">
        {showCancel && (
          <button
            className="btn btn-ghost"
            onClick={() => post({ type: "resolve-dapp-dialog", id: dialog.id, action: "cancel" })}
          >
            {dialog.labels.cancel}
          </button>
        )}
        <button
          className="btn btn-primary"
          autoFocus={!isPrompt}
          onClick={() => post({ type: "resolve-dapp-dialog", id: dialog.id, action: "ok", value })}
        >
          {dialog.labels.ok}
        </button>
      </div>
    </div>
  );
}

function AcctMenu({ menu }: { menu: Extract<MenuOverlayPayload, { kind: "account" }> }) {
  const [query, setQuery] = useState("");
  return (
    <BrowserAccountMenu
      accounts={menu.accounts}
      activeAddress={menu.activeAddress}
      query={query}
      onQueryChange={setQuery}
      onSelect={(address) => post({ type: "select-account", address })}
      onDismiss={() => post({ type: "dismiss" })}
      copyTitle={menu.copyTitle}
      onCopied={() => post({ type: "copy-result", success: true })}
      onCopyFailed={() => post({ type: "copy-result", success: false })}
    />
  );
}

// Markup mirrors ChainChip's in-shell dropdown (BrowserView.tsx).
function ChainMenu({ menu }: { menu: Extract<MenuOverlayPayload, { kind: "chain" }> }) {
  const { t } = useT();
  const [query, setQuery] = useState("");
  const filteredChains = useMemo(() => filterChains(menu.chains, query), [menu.chains, query]);

  return (
    <>
      <label className="chain-search">
        <Icon name="search" size={15} />
        <input
          value={query}
          autoFocus
          aria-label={t("browser.searchNetworks")}
          placeholder={t("browser.searchNetworks")}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>
      <div className="chain-list scroll">
        {filteredChains.map((c) => (
          <button
            key={c.id}
            className={`chain-opt${c.id === menu.activeChainId ? " on" : ""}`}
            onClick={() => post({ type: "select-chain", id: c.id })}
          >
            <ChainIcon chain={c} size={20} />
            <span className="nm">{c.name}</span>
            {c.id === menu.activeChainId && (
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
    </>
  );
}
