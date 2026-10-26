import { useCallback, useEffect, useRef, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import "./App.css";
import mascot from "./assets/mascot.png";
import logoMark from "./assets/auto-desktop-mark.png";
import logoWordmark from "./assets/auto-desktop-wordmark.png";
import WalletPage from "./pages/WalletPage";
import DappsPage from "./pages/DappsPage";
import BrowserView from "./pages/BrowserView";
import SettingsPage from "./pages/SettingsPage";
import OkxPage from "./pages/OkxPage";
import LockScreen from "./pages/LockScreen";
import { ensureDapp, type Dapp } from "./lib/dapps";
import { forgetDappLoad } from "./lib/dappLoadState";
import { closeDappTabs } from "./lib/dappTabs";
import {
  closeDapp,
  dappLabel,
  hideDapp,
  isTauri,
  openExternalUrl,
  rectOf,
  resolveDappDialog,
  syncToastOverlay,
} from "./lib/platform";
import { refreshVaultStatus, useVault } from "./lib/vault";
import { createActivityReporter } from "./lib/autoLock";
import { invoke } from "@tauri-apps/api/core";
import { useActiveAccountSync } from "./lib/accounts";
import { findChain, loadChains } from "./lib/chains";
import { useT } from "./lib/i18n";
import { Icon } from "./lib/icons";
import { setThemePref, useEffectiveTheme } from "./lib/theme";
import { shortAddress } from "./lib/format";
import { ConfirmHost, ToastHost, DappIcon } from "./lib/ui";
import { toast, useToasts } from "./lib/toast";
import {
  loadActivity,
  syncActivityReceipts,
  useActivity,
  type ActivityRecord,
} from "./lib/activity";
import { txExplorerUrl } from "./lib/explorer";
import { useMenuOverlay, type MenuOverlayPayload } from "./lib/menuOverlay";
import { SidebarFooter } from "./SidebarFooter";
import { setNativeMenuLanguage } from "./lib/nativeMenu";
import { autoUpdater, useAutoUpdate } from "./lib/autoUpdater";

type Page = "wallet" | "okx" | "dapps" | "browser" | "settings";
type Tab = { id: string; dapp: Dapp };
type DappDialogEvent = {
  id: string;
  kind: "alert" | "confirm" | "prompt" | "print";
  origin: string;
  message: string;
  default_value?: string | null;
};

const SIDEBAR_KEY = "autodesktop.sidebarCollapsed";

function App() {
  const vault = useVault();
  const { t, lang } = useT();
  const activity = useActivity();
  const txStatusRef = useRef<Map<string, string>>(new Map());
  const notifiedTxRef = useRef<Set<string>>(new Set());
  const submittedThisSessionRef = useRef<Set<string>>(new Set());
  useEffect(() => {
    if (isTauri()) void autoUpdater.start();
  }, []);
  const showTxToast = useCallback(
    (
      record: ActivityRecord | undefined,
      messageKey:
        | "wallet.txSubmitted"
        | "wallet.txUnconfirmed"
        | "wallet.txConfirmed"
        | "wallet.txFailed",
      kind: "ok" | "info" | "warn" = "ok",
      status?: string,
    ) => {
      const hash = record?.hash;
      if (record && status) {
        if (status === "submitted") {
          submittedThisSessionRef.current.add(record.id);
        } else if (!submittedThisSessionRef.current.has(record.id)) {
          return;
        }
        const key = `${record.id}:${status}`;
        if (notifiedTxRef.current.has(key)) return;
        notifiedTxRef.current.add(key);
      }
      const href = record ? txExplorerUrl(findChain(record.chainId), record) : null;
      toast(
        t(messageKey, { hash: hash ? shortAddress(hash, 8, 6) : "" }),
        kind,
        href
          ? {
              label: t("wallet.openExplorer"),
              url: href,
              onClick: () => void openExternalUrl(href),
            }
          : undefined,
        { card: true, durationMs: 6000 },
      );
    },
    [t],
  );
  // Reconcile the backend's active signer with the shell's remembered selection so a
  // dApp always connects to the account shown in the sidebar (and follows wallet
  // switches). Backend resets to the first account on every unlock; this re-syncs it.
  useActiveAccountSync();

  useEffect(() => {
    void setNativeMenuLanguage(lang).catch((error) => {
      console.error("[AutoDesktop] failed to localize the native menu", error);
    });
  }, [lang]);

  // Gate the whole app behind the vault: load its status on boot, then show the
  // lock/setup screen until the wallet is unlocked for this session. A backend
  // already unlocked on boot (vite HMR during dev) opens the gate without a prompt.
  const [sessionUnlocked, setSessionUnlocked] = useState(false);
  const phaseRef = useRef(vault.phase);
  phaseRef.current = vault.phase;
  useEffect(() => {
    void loadChains();
    void refreshVaultStatus().then(() => {
      if (phaseRef.current === "unlocked") setSessionUnlocked(true);
    });
  }, []);
  useEffect(() => {
    if (vault.phase === "locked" || vault.phase === "absent")
      setSessionUnlocked(false);
  }, [vault.phase]);
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    const unlisteners: (() => void)[] = [];
    void listen<ActivityRecord>("activity-recorded", (event) => {
      showTxToast(event.payload, "wallet.txSubmitted", "info", "submitted");
    }).then((fn) => {
      if (disposed) fn();
      else unlisteners.push(fn);
    });
    // Signed and handed to the node, which then went quiet. The transaction is
    // recorded and polled like any other, so this warns rather than reporting a
    // failure — resending is the one thing that could actually cost money here.
    void listen<ActivityRecord>("activity-unconfirmed", (event) => {
      showTxToast(event.payload, "wallet.txUnconfirmed", "warn", "submitted");
    }).then((fn) => {
      if (disposed) fn();
      else unlisteners.push(fn);
    });
    void listen<ActivityRecord>("activity-confirmed", (event) => {
      showTxToast(event.payload, "wallet.txConfirmed", "ok", "confirmed");
    }).then((fn) => {
      if (disposed) fn();
      else unlisteners.push(fn);
    });
    void listen<ActivityRecord>("activity-failed", (event) => {
      showTxToast(event.payload, "wallet.txFailed", "warn", "failed");
    }).then((fn) => {
      if (disposed) fn();
      else unlisteners.push(fn);
    });
    return () => {
      disposed = true;
      for (const unlisten of unlisteners) unlisten();
    };
  }, [lang, showTxToast]);
  useEffect(() => {
    if (!isTauri() || !sessionUnlocked) return;
    void loadActivity().catch(() => undefined);
    void syncActivityReceipts().catch(() => undefined);
    const id = window.setInterval(() => {
      void syncActivityReceipts().catch(() => undefined);
    }, 8_000);
    return () => window.clearInterval(id);
  }, [sessionUnlocked]);
  useEffect(() => {
    if (!isTauri()) return;
    const prev = txStatusRef.current;
    const next = new Map<string, string>();
    for (const record of activity) {
      const status = record.status ?? "submitted";
      const old = prev.get(record.id);
      next.set(record.id, status);
      if (old === "submitted" && status === "confirmed") {
        if (submittedThisSessionRef.current.has(record.id)) {
          showTxToast(record, "wallet.txConfirmed", "ok", "confirmed");
        }
      } else if (old === "submitted" && status === "failed") {
        if (submittedThisSessionRef.current.has(record.id)) {
          showTxToast(record, "wallet.txFailed", "warn", "failed");
        }
      }
    }
    txStatusRef.current = next;
  }, [activity, showTxToast]);

  const [page, setPage] = useState<Page>("wallet");

  // Auto-lock: user input in the shell restarts the backend idle timer (dApp
  // calls restart it on the Rust side), and an idle lock sends the UI to the
  // lock screen.
  useEffect(() => {
    if (!isTauri()) return;
    const report = createActivityReporter(30_000, Date.now, () => {
      invoke("note_user_activity").catch((e) =>
        console.error("[AutoDesktop] note_user_activity failed", e),
      );
    });
    const events = ["pointerdown", "keydown", "wheel"] as const;
    for (const ev of events) window.addEventListener(ev, report, { passive: true });
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen("vault-locked", () => void refreshVaultStatus()).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
      for (const ev of events) window.removeEventListener(ev, report);
    };
  }, []);
  const [dappDialog, setDappDialog] =
    useState<Extract<MenuOverlayPayload, { kind: "dialog" }> | null>(null);
  useEffect(() => {
    if (!isTauri()) return;
    let disposed = false;
    let unlisten: (() => void) | null = null;
    void listen<DappDialogEvent>("dapp-dialog-request", (event) => {
      const req = event.payload;
      if (!req?.id) return;
      setDappDialog({
        kind: "dialog",
        id: req.id,
        dialogKind: req.kind,
        origin: req.origin,
        message: req.message,
        defaultValue: req.default_value,
        labels: {
          title: t("browser.dialogTitle"),
          ok: t("common.ok"),
          cancel: t("common.cancel"),
          promptPlaceholder: t("browser.promptPlaceholder"),
        },
      });
    }).then((fn) => {
      if (disposed) fn();
      else unlisten = fn;
    });
    return () => {
      disposed = true;
      unlisten?.();
    };
  }, [lang]);
  useMenuOverlay(dappDialog, (action) => {
    if (action.type !== "resolve-dapp-dialog" && action.type !== "dismiss") return;
    const id = action.type === "resolve-dapp-dialog" ? action.id : dappDialog?.id;
    if (!id) return;
    const decision = action.type === "resolve-dapp-dialog" ? action.action : "cancel";
    const value = action.type === "resolve-dapp-dialog" ? action.value : null;
    setDappDialog(null);
    void resolveDappDialog(id, decision, value).catch(() => undefined);
  });
  const [collapsed, setCollapsed] = useState<boolean>(
    () => {
      const saved = localStorage.getItem(SIDEBAR_KEY);
      if (saved != null) return saved === "1";
      return window.innerWidth < 1180;
    },
  );
  function toggleSidebar() {
    setCollapsed((c) => {
      localStorage.setItem(SIDEBAR_KEY, c ? "0" : "1");
      return !c;
    });
  }

  // Every open dApp is a persistent tab (its own native webview); switching tabs
  // just shows/hides them. VISION feature ②③.
  const [tabs, setTabs] = useState<Tab[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [closingTabs, setClosingTabs] = useState(false);
  const activeIdRef = useRef(activeId);
  activeIdRef.current = activeId;
  const activeTab = tabs.find((t) => t.id === activeId) ?? null;

  function openTab(dapp: Dapp) {
    setTabs((prev) =>
      prev.some((t) => t.id === dapp.id)
        ? prev
        : [...prev, { id: dapp.id, dapp }],
    );
    setActiveId(dapp.id);
    setPage("browser");
  }

  useEffect(() => {
    const onOpenDapp = (event: Event) => {
      const dapp = (event as CustomEvent<Dapp>).detail;
      if (!dapp?.id || !dapp.url || !dapp.name) return;
      openTab(ensureDapp(dapp.url, dapp.name));
    };
    window.addEventListener("autodesktop:open-dapp", onOpenDapp);
    return () => window.removeEventListener("autodesktop:open-dapp", onOpenDapp);
  }, []);

  function closeTab(id: string) {
    void closeDapp(dappLabel(id));
    // The webview dies with the tab, so the next open reloads the page and has
    // to show the loading animation again.
    forgetDappLoad(dappLabel(id));
    const remaining = tabs.filter((t) => t.id !== id);
    setTabs(remaining);
    if (activeId === id) {
      const next = remaining[remaining.length - 1] ?? null;
      setActiveId(next?.id ?? null);
      setPage(next ? "browser" : "dapps");
    }
  }

  async function closeAllTabs() {
    if (closingTabs) return;
    setClosingTabs(true);
    const { closed, failed } = await closeDappTabs(tabs.map((tab) => tab.id));
    const closedIds = new Set(closed);
    setTabs((current) => current.filter((tab) => !closedIds.has(tab.id)));
    // The user may switch pages or tabs while the native views are closing.
    const selected = activeIdRef.current;
    if (selected !== null && closedIds.has(selected)) {
      setActiveId(null);
      setPage((current) => current === "browser" ? "dapps" : current);
    }
    if (failed.length > 0) {
      for (const failure of failed) {
        console.error(`[AutoDesktop] close dApp failed for ${failure.id}`, failure.error);
      }
      toast(t("dapps.closeFailed"), "warn");
    }
    setClosingTabs(false);
  }

  useEffect(() => {
    if (!isTauri() || page === "browser") return;
    for (const tab of tabs) {
      void hideDapp(dappLabel(tab.id)).catch(() => undefined);
    }
  }, [page, tabs]);

  if (vault.phase === "loading") {
    return (
      <div className="boot">
        <img src={mascot} alt="" width={48} height={48} />
      </div>
    );
  }
  if (!sessionUnlocked) {
    return (
      <>
        <LockScreen onDone={() => setSessionUnlocked(true)} />
        <AutoUpdateNotice />
        <ToastHost />
        <ConfirmHost />
      </>
    );
  }

  return (
    <div className="app">
      <Sidebar
        collapsed={collapsed}
        onToggle={toggleSidebar}
        page={page}
        setPage={setPage}
        tabs={tabs}
        activeId={activeId}
        onOpenTab={(id) => {
          setActiveId(id);
          setPage("browser");
        }}
        onCloseTab={closeTab}
        onCloseAllTabs={() => void closeAllTabs()}
        closingTabs={closingTabs}
      />

      <main className="main">
        <AutoUpdateNotice />
        {page === "wallet" && <WalletPage />}
        {page === "okx" && <OkxPage />}
        {page === "dapps" && <DappsPage onOpen={openTab} />}
        {page === "browser" && activeTab && (
          <BrowserView
            key={activeTab.id}
            tab={activeTab}
            onBack={() => setPage("dapps")}
          />
        )}
        {page === "settings" && <SettingsPage />}
      </main>

      <ToastHost />
      <ConfirmHost />
      <NativeToastOverlay active={page === "browser"} />
    </div>
  );
}

function AutoUpdateNotice() {
  const { t } = useT();
  const update = useAutoUpdate();
  if (update.status !== "ready" && update.status !== "installing") return null;

  return (
    <aside className="auto-update-notice" role="status" aria-live="polite">
      <span className="auto-update-icon" aria-hidden="true">
        <Icon name="download" size={17} />
      </span>
      <div className="auto-update-copy">
        <strong>
          {t("update.ready", { version: update.version ?? "" })}
        </strong>
        {update.error && <small>{t("update.installFailed", { error: update.error })}</small>}
      </div>
      <div className="auto-update-actions">
        <button
          type="button"
          className="auto-update-accept"
          disabled={update.status === "installing"}
          onClick={() => void autoUpdater.install()}
        >
          {update.status === "installing" ? t("update.installing") : t("update.install")}
        </button>
        <button
          type="button"
          className="auto-update-ignore"
          disabled={update.status === "installing"}
          onClick={() => void autoUpdater.ignore()}
        >
          {t("update.ignore")}
        </button>
      </div>
    </aside>
  );
}

function NativeToastOverlay({ active }: { active: boolean }) {
  const toasts = useToasts();
  useEffect(() => {
    if (!isTauri()) return;
    if (!active) {
      localStorage.removeItem("autodesktop.toastOverlayPayload");
      void syncToastOverlay(null).catch(() => undefined);
      return;
    }

    const id = requestAnimationFrame(() => {
      const wrap = document.querySelector<HTMLElement>(".app > .toast-wrap");
      if (!wrap || toasts.length === 0) {
        localStorage.removeItem("autodesktop.toastOverlayPayload");
        void syncToastOverlay(null).catch(() => undefined);
        return;
      }
      const measured = rectOf(wrap);
      const pad = 48;
      const leftPad = Math.min(measured.x, pad);
      const topPad = Math.min(measured.y, pad);
      const rect = {
        x: measured.x - leftPad,
        y: measured.y - topPad,
        w: measured.w + leftPad,
        h: measured.h + topPad,
      };
      const payload = {
        toasts: toasts.map((t) => ({
          id: t.id,
          msg: t.msg,
          kind: t.kind,
          card: t.card,
          actionLabel: t.action?.label,
          actionUrl: t.action?.url,
        })),
      };
      localStorage.setItem("autodesktop.toastOverlayPayload", JSON.stringify(payload));
      void syncToastOverlay(rect).then(() => {
        const channel = new BroadcastChannel("autodesktop-toast-overlay");
        channel.postMessage(payload);
        window.setTimeout(() => channel.postMessage(payload), 80);
        window.setTimeout(() => channel.close(), 160);
      }).catch(() => undefined);
    });

    return () => cancelAnimationFrame(id);
  }, [active, toasts]);

  return null;
}

function Sidebar({
  collapsed,
  onToggle,
  page,
  setPage,
  tabs,
  activeId,
  onOpenTab,
  onCloseTab,
  onCloseAllTabs,
  closingTabs,
}: {
  collapsed: boolean;
  onToggle: () => void;
  page: Page;
  setPage: (p: Page) => void;
  tabs: Tab[];
  activeId: string | null;
  onOpenTab: (id: string) => void;
  onCloseTab: (id: string) => void;
  onCloseAllTabs: () => void;
  closingTabs: boolean;
}) {
  const { t } = useT();
  const theme = useEffectiveTheme();

  const nav: {
    key: "wallet" | "okx" | "dapps";
    i18n: string;
    icon: "wallet" | "okx" | "compass";
  }[] = [
    { key: "wallet", i18n: "nav.wallet", icon: "wallet" },
    { key: "okx", i18n: "nav.okx", icon: "okx" },
    { key: "dapps", i18n: "nav.explore", icon: "compass" },
  ];

  return (
    <aside className={`sidebar${collapsed ? " collapsed" : ""}`}>
      <div className="side-top">
        <div className="brand">
          <img
            className={collapsed ? "brand-mark" : "brand-wordmark"}
            src={collapsed ? logoMark : logoWordmark}
            alt="AutoDesktop"
          />
        </div>
        <button
          className="icon-btn bare side-toggle"
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          onClick={onToggle}
          style={collapsed ? { alignSelf: "center" } : undefined}
        >
          <Icon name="sidebar" size={17} />
        </button>
      </div>

      <nav className="nav">
        {nav.map((item) => (
          <button
            key={item.key}
            className={`nav-item${page === item.key ? " active" : ""}`}
            title={collapsed ? t(item.i18n) : ""}
            onClick={() => setPage(item.key)}
          >
            <span className="nav-ic">
              <Icon name={item.icon} size={19} sw={item.icon === "okx" ? 0 : undefined} fill={item.icon === "okx" ? "currentColor" : undefined} />
            </span>
            {!collapsed && <span className="nav-label">{t(item.i18n)}</span>}
          </button>
        ))}

        {tabs.length > 0 && (
          <>
            {!collapsed ? (
              <div className="nav-section">
                <span>{t("nav.opened")}</span>
                <button
                  className="tabs-close-all"
                  onClick={onCloseAllTabs}
                  disabled={closingTabs}
                >
                  {t("dapps.closeAll")}
                </button>
              </div>
            ) : (
              <div style={{ height: 12 }} />
            )}
            {tabs.map((tab) => (
              <div
                key={tab.id}
                className={`nav-item tab-item${page === "browser" && tab.id === activeId ? " active" : ""}`}
                title={collapsed ? tab.dapp.name : ""}
                onClick={() => onOpenTab(tab.id)}
              >
                <DappIcon
                  className="tab-fav"
                  url={tab.dapp.url}
                  name={tab.dapp.name}
                  refreshAt={tab.dapp.iconRefreshAt}
                  size={18}
                  radius={5}
                />
                {!collapsed && (
                  <>
                    <span className="tab-name">{tab.dapp.name}</span>
                    <button
                      className="tab-close"
                      title="Close tab"
                      onClick={(e) => {
                        e.stopPropagation();
                        onCloseTab(tab.id);
                      }}
                    >
                      <Icon name="close" size={13} />
                    </button>
                  </>
                )}
              </div>
            ))}
          </>
        )}
      </nav>

      <button
        className={`nav-item${page === "settings" ? " active" : ""}`}
        title={collapsed ? t("nav.settings") : ""}
        onClick={() => setPage("settings")}
        style={{ marginBottom: 8 }}
      >
        <span className="nav-ic">
          <Icon name="settings" size={19} />
        </span>
        {!collapsed && <span className="nav-label">{t("nav.settings")}</span>}
      </button>

      <SidebarFooter
        collapsed={collapsed}
        theme={theme}
        onThemeChange={setThemePref}
      />
    </aside>
  );
}

export default App;
