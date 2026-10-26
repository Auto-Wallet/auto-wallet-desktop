import { useEffect, useMemo, useState } from "react";
import "./SettingsPage.css";
import { ChangePasswordModal } from "./ChangePasswordModal";
import logoMark from "../assets/auto-desktop-mark.png";
import {
  addChain,
  removeChain,
  updateChain,
  useChains,
  type Chain,
} from "../lib/chains";
import { setActiveChain, useActiveChain } from "../lib/activeChain";
import {
  disableTouchId,
  enableTouchId,
  exportWalletSecret,
  getTouchIdStatus,
  lockVault,
  type TouchIdStatus,
  type ExportedSecret,
  type WalletInfo,
  useVault,
} from "../lib/vault";
import { useActiveWallet } from "../lib/accounts";
import { setLang, useT, type Lang, type TFn } from "../lib/i18n";
import { setThemePref, useThemePref, type ThemePref } from "../lib/theme";
import { setCloseBehavior, useCloseBehavior } from "../lib/appPrefs";
import {
  checkForUpdate,
  installUpdate,
  type UpdateInfo,
  type UpdateProgress,
} from "../lib/updater";
import { updateBarState } from "../lib/updateBar";
import { openExternalUrl } from "../lib/platform";
import { useModalExit, useSegPill, useToggleInit } from "../lib/transitions";
import { Icon, type IconName } from "../lib/icons";
import { CopyButton } from "../lib/ui";
import { askConfirm } from "../lib/confirm";
import { toast } from "../lib/toast";
import { ChainIcon } from "../lib/ChainIcon";
import { filterSettingsChains } from "./networkSettings";
import { securityRows } from "./securityRows";
import { listen } from "@tauri-apps/api/event";
import { AUTO_LOCK_CHOICES, getAutoLockMinutes, setAutoLockMinutes } from "../lib/autoLock";
import { disconnectSite, loadConnectedSites } from "../lib/connectedSites";
import { isTauri } from "../lib/platform";

const APP_VERSION = __APP_VERSION__;

function safeHost(rpc: string): string {
  try {
    return new URL(rpc).hostname;
  } catch {
    return rpc;
  }
}
function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

export default function SettingsPage() {
  const { t, lang } = useT();
  const chains = useChains();
  const activeChain = useActiveChain();
  const themePref = useThemePref();
  const themeSegRef = useSegPill<HTMLDivElement>(themePref);
  const langSegRef = useSegPill<HTMLDivElement>(lang);
  const closeBehavior = useCloseBehavior();
  const closeToggle = useToggleInit(closeBehavior === "hide");
  const vault = useVault();
  const activeWallet = useActiveWallet();
  const security = securityRows({
    hasPassword: vault.hasPassword,
    activeKind: activeWallet?.kind,
  });
  const [touchIdStatus, setTouchIdStatus] = useState<TouchIdStatus | null>(null);
  const [touchIdBusy, setTouchIdBusy] = useState(false);
  const [changingPassword, setChangingPassword] = useState(false);
  const touchIdEnabled = touchIdStatus !== null && touchIdStatus.enabled;
  const touchIdToggle = useToggleInit(touchIdEnabled);
  const [updated, setUpdated] = useState(false);
  const [checkingUpdate, setCheckingUpdate] = useState(false);
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [updateProgress, setUpdateProgress] = useState<UpdateProgress | null>(
    null,
  );
  const [exportingWallet, setExportingWallet] = useState<WalletInfo | null>(
    null,
  );
  const [editing, setEditing] = useState<Chain | "new" | null>(null);
  const [autoLockMinutes, setAutoLockState] = useState<number | null>(null);
  const [connectedSites, setConnectedSites] = useState<string[]>([]);
  const [networkQuery, setNetworkQuery] = useState("");
  const visibleChains = useMemo(
    () => filterSettingsChains(chains, networkQuery),
    [chains, networkQuery],
  );

  const themeOpts: [ThemePref, IconName, string][] = [
    ["system", "monitor", t("settings.system")],
    ["light", "sun", t("settings.light")],
    ["dark", "moon", t("settings.dark")],
  ];
  const updateButtonLabel = checkingUpdate
    ? updateInfo?.available
      ? t("settings.installingUpdate")
      : t("settings.checkingUpdates")
    : updateInfo?.available
      ? t("settings.installUpdate")
      : t("settings.checkUpdates");

  useEffect(() => {
    let active = true;
    void getTouchIdStatus()
      .then((status) => {
        if (active) setTouchIdStatus(status);
      })
      .catch((error) => {
        if (active) toast(t("settings.touchIdFailed", { error: errText(error) }), "warn");
      });
    return () => {
      active = false;
    };
  }, [t]);

  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    void getAutoLockMinutes()
      .then((m) => {
        if (active) setAutoLockState(m);
      })
      .catch((error) => toast(errText(error), "warn"));
    const reload = () =>
      void loadConnectedSites()
        .then((list) => {
          if (active) setConnectedSites(list);
        })
        .catch((error) => toast(errText(error), "warn"));
    reload();
    // A dApp connecting (approval window) or revoking itself changes the list.
    let unlisten: (() => void) | null = null;
    void listen("connected-sites-changed", reload).then((fn) => {
      if (active) unlisten = fn;
      else fn();
    });
    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  function autoLockLabel(m: number): string {
    if (m === 0) return t("settings.autoLockNever");
    return m >= 60 ? t("settings.autoLockHours", { n: m / 60 }) : t("settings.autoLockMinutes", { n: m });
  }

  async function handleTouchIdToggle() {
    if (touchIdStatus === null || touchIdBusy) return;
    if (!touchIdStatus.enabled) {
      const confirmed = await askConfirm({
        title: t("settings.touchIdConfirmTitle"),
        message: t("settings.touchIdConfirmMessage"),
        confirmLabel: t("settings.touchIdConfirm"),
      });
      if (!confirmed) return;
    }

    setTouchIdBusy(true);
    try {
      if (touchIdStatus.enabled) {
        await disableTouchId();
        setTouchIdStatus({ available: touchIdStatus.available, enabled: false });
        toast(t("settings.touchIdDisabled"));
      } else {
        await enableTouchId(t("settings.touchIdEnableReason"));
        setTouchIdStatus({ available: touchIdStatus.available, enabled: true });
        toast(t("settings.touchIdEnabled"));
      }
    } catch (error) {
      toast(t("settings.touchIdFailed", { error: errText(error) }), "warn");
    } finally {
      setTouchIdBusy(false);
    }
  }

  async function handleCheckUpdates() {
    if (updateInfo?.available && !updateInfo.manual) {
      await handleInstallUpdate();
      return;
    }
    setCheckingUpdate(true);
    setUpdated(false);
    setUpdateProgress(null);
    try {
      const info = await checkForUpdate();
      setUpdateInfo(info);
      if (!info.available) {
        setUpdated(true);
        toast(t("settings.upToDate"));
        return;
      }
      if (info.manual) {
        toast(
          t("settings.updateAutoUnavailable", {
            error: info.autoError || t("settings.unknownError"),
          }),
          "warn",
        );
        return;
      }
      toast(t("settings.updateAvailable", { version: info.latestVersion }));
    } catch (e) {
      toast(t("settings.updateFailed", { error: errText(e) }), "warn");
    } finally {
      setCheckingUpdate(false);
    }
  }

  async function handleInstallUpdate() {
    if (!updateInfo?.available) return;
    setCheckingUpdate(true);
    setUpdateProgress({ phase: "downloading", downloaded: 0 });
    try {
      const info = await installUpdate(
        { ...updateInfo, manual: false },
        setUpdateProgress,
      );
      setUpdateInfo(info);
      if (!info.available) {
        setUpdated(true);
        toast(t("settings.upToDate"));
        return;
      }
      if (info.manual) {
        toast(
          t("settings.updateAutoFailed", {
            error: info.autoError || t("settings.unknownError"),
          }),
          "warn",
        );
        return;
      }
      toast(t("settings.updateInstalled", { version: info.latestVersion }));
    } catch (e) {
      toast(t("settings.updateFailed", { error: errText(e) }), "warn");
    } finally {
      setCheckingUpdate(false);
      setUpdateProgress(null);
    }
  }

  async function handleManualDownload() {
    if (!updateInfo?.available) return;
    const url = updateInfo.downloadUrl || updateInfo.releaseUrl;
    await openExternalUrl(url);
    toast(t("settings.updateOpened", { version: updateInfo.latestVersion }));
  }

  const updateBar = updateProgress ? updateBarState(updateProgress) : null;

  return (
    <>
      <div className="topbar">
        <div className="topbar-title">{t("settings.title")}</div>
      </div>

      {exportingWallet && (
        <ExportSecretModal
          wallet={exportingWallet}
          t={t}
          onClose={() => setExportingWallet(null)}
        />
      )}

      {changingPassword && (
        <ChangePasswordModal
          onClose={() => setChangingPassword(false)}
          onChanged={(result) => {
            setTouchIdStatus((status) => status === null ? null : { ...status, enabled: result.touchIdEnabled });
            toast(
              result.warning === null
                ? t("settings.passwordChanged")
                : t("settings.passwordChangedWarning", { detail: result.warning }),
              result.warning === null ? "ok" : "warn",
            );
          }}
        />
      )}

      {editing && (
        <NetworkForm
          t={t}
          initial={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}

      <div className="page scroll">
        <div className="settings-pad">
          {/* Networks */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="globe" size={16} /> {t("settings.network")}
              </h2>
              <p>{t("settings.networkHint")}</p>
            </div>
            <div className="network-tools">
              <label className="network-search">
                <Icon name="search" size={16} />
                <input
                  className="input"
                  type="search"
                  value={networkQuery}
                  onChange={(event) => setNetworkQuery(event.target.value)}
                  placeholder={t("settings.searchNetworks")}
                  aria-label={t("settings.searchNetworks")}
                />
              </label>
              <button
                className="add-net"
                type="button"
                onClick={() => setEditing("new")}
              >
                <Icon name="plus" size={16} /> {t("settings.addNetwork")}
              </button>
            </div>
            <div className="set-card network-list scroll">
              {visibleChains.map((c) => {
                const on = c.id.toLowerCase() === activeChain.toLowerCase();
                return (
                  <div key={c.id} className={`chain-row${on ? " on" : ""}`}>
                    <button
                      className="chain-pick"
                      type="button"
                      aria-pressed={on}
                      onClick={() => void setActiveChain(c.id)}
                    >
                      <span className="chain-radio" />
                      <ChainIcon chain={c} size={26} />
                      <div className="chain-info">
                        <div className="chain-nm">
                          {c.name}
                          {c.builtin && (
                            <span className="badge neutral">
                              {t("settings.builtin")}
                            </span>
                          )}
                        </div>
                        <div className="chain-meta">
                          {c.symbol} · {c.id} · {safeHost(c.rpc)}
                          {c.explorerUrl ? ` · ${safeHost(c.explorerUrl)}` : ""}
                        </div>
                      </div>
                    </button>
                    <div className="chain-acts">
                      <button
                        className="icon-btn bare"
                        type="button"
                        title={t("settings.edit")}
                        onClick={() => setEditing(c)}
                      >
                        <Icon name="edit" size={16} />
                      </button>
                      {!c.builtin && (
                        <button
                          className="icon-btn bare"
                          type="button"
                          title={t("settings.remove")}
                          onClick={async () => {
                            if (
                              await askConfirm({
                                title: t("settings.removeConfirm"),
                                confirmLabel: t("settings.remove"),
                                danger: true,
                              })
                            ) {
                              await removeChain(c.id);
                              toast(t("dapps.removed"));
                            }
                          }}
                        >
                          <Icon name="trash" size={16} />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
              {visibleChains.length === 0 && (
                <div className="network-empty">
                  <Icon name="search" size={18} />
                  {t("settings.noNetworkMatches")}
                </div>
              )}
            </div>
          </div>

          {/* Appearance */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="sun" size={16} /> {t("settings.appearance")}
              </h2>
              <p>{t("settings.appearanceHint")}</p>
            </div>
            <div className="set-card">
              <div className="set-row">
                <div className="gr">
                  <div className="rl">{t("settings.theme")}</div>
                  <div className="rs">{t("settings.themeHint")}</div>
                </div>
                <div className="seg" ref={themeSegRef}>
                  <span className="t-tabs-pill" aria-hidden="true" />
                  {themeOpts.map(([v, ic, lbl]) => (
                    <button
                      key={v}
                      className={themePref === v ? "on" : ""}
                      onClick={() => setThemePref(v)}
                    >
                      <Icon name={ic} size={15} /> {lbl}
                    </button>
                  ))}
                </div>
              </div>
              <div className="set-row">
                <div className="gr">
                  <div className="rl">{t("settings.closeBehavior")}</div>
                  <div className="rs">{t("settings.closeBehaviorHint")}</div>
                </div>
                <button
                  className={`toggle t-toggle${closeToggle.initCls}${
                    closeBehavior === "hide" ? " on" : ""
                  }`}
                  data-on={closeToggle.dataOn}
                  aria-pressed={closeBehavior === "hide"}
                  onClick={() =>
                    void setCloseBehavior(
                      closeBehavior === "hide" ? "quit" : "hide",
                    )
                  }
                >
                  <i className="t-toggle-thumb" />
                </button>
              </div>
            </div>
          </div>

          {/* Language */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="globe" size={16} /> {t("settings.language")}
              </h2>
              <p>{t("settings.languageHint")}</p>
            </div>
            <div className="set-card">
              <div className="set-row">
                <div className="gr">
                  <div className="rl">{t("settings.language")}</div>
                  <div className="rs">English · 中文</div>
                </div>
                <div className="seg" ref={langSegRef}>
                  <span className="t-tabs-pill" aria-hidden="true" />
                  {(["en", "zh"] as Lang[]).map((l) => (
                    <button
                      key={l}
                      className={lang === l ? "on" : ""}
                      onClick={() => setLang(l)}
                    >
                      {l === "en" ? "English" : "中文"}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Security */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="shield" size={16} /> {t("settings.security")}
              </h2>
            </div>
            <div className="set-card">
              {security.ledgerNote && (
                <div className="set-row">
                  <span className="row-ic">
                    <Icon name="ledger" size={17} />
                  </span>
                  <div className="gr">
                    <div className="rl">Ledger</div>
                    <div className="rs">{t("lock.optLedgerDesc")}</div>
                  </div>
                </div>
              )}
              {security.lockNow && (
                <button className="set-row" onClick={() => void lockVault()}>
                  <span className="row-ic">
                    <Icon name="lock" size={17} />
                  </span>
                  <div className="gr">
                    <div className="rl">{t("settings.lockNow")}</div>
                    <div className="rs">{t("settings.lockNowHint")}</div>
                  </div>
                  <Icon name="chevronR" size={16} />
                </button>
              )}
              {(activeWallet?.kind === "hd" ||
                activeWallet?.kind === "privkey") && (
                <button
                  className="set-row"
                  onClick={() => setExportingWallet(activeWallet)}
                >
                  <span className="row-ic">
                    <Icon name="key" size={17} />
                  </span>
                  <div className="gr">
                    <div className="rl">
                      {t(
                        activeWallet.kind === "hd"
                          ? "settings.revealPhrase"
                          : "settings.revealPrivateKey",
                      )}
                    </div>
                    <div className="rs">
                      {t(
                        activeWallet.kind === "hd"
                          ? "settings.revealPhraseHint"
                          : "settings.revealPrivateKeyHint",
                      )}
                    </div>
                  </div>
                  <Icon name="chevronR" size={16} />
                </button>
              )}
              {security.changePassword && (
                <button
                  className="set-row"
                  disabled={!vault.hasPassword || touchIdBusy}
                  onClick={() => setChangingPassword(true)}
                >
                  <span className="row-ic">
                    <Icon name="edit" size={17} />
                  </span>
                  <div className="gr">
                    <div className="rl">{t("settings.changePassword")}</div>
                    <div className="rs">
                      {t("settings.changePasswordHint")}
                    </div>
                  </div>
                  <Icon name="chevronR" size={16} />
                </button>
              )}
              {vault.hasPassword &&
                touchIdStatus !== null &&
                touchIdStatus.available && (
                  <div className="set-row">
                    <span className="row-ic touch-id-row-ic">
                      <Icon name="fingerprint" size={18} />
                    </span>
                    <div className="gr">
                      <div className="rl">{t("settings.touchId")}</div>
                      <div className="rs">{t("settings.touchIdHint")}</div>
                    </div>
                    <button
                      className={`toggle t-toggle${touchIdToggle.initCls}${
                        touchIdStatus.enabled ? " on" : ""
                      }`}
                      data-on={touchIdToggle.dataOn}
                      aria-label={t("settings.touchId")}
                      aria-pressed={touchIdStatus.enabled}
                      disabled={touchIdBusy || changingPassword}
                      onClick={() => void handleTouchIdToggle()}
                    >
                      <i className="t-toggle-thumb" />
                    </button>
                  </div>
                )}
              {vault.hasPassword && autoLockMinutes !== null && (
                <div className="set-row">
                  <span className="row-ic">
                    <Icon name="lock" size={17} />
                  </span>
                  <div className="gr">
                    <div className="rl">{t("settings.autoLock")}</div>
                    <div className="rs">{t("settings.autoLockHint")}</div>
                  </div>
                  <select
                    className="input auto-lock-select"
                    aria-label={t("settings.autoLock")}
                    value={autoLockMinutes}
                    onChange={(e) => {
                      const next = Number(e.target.value);
                      void setAutoLockMinutes(next)
                        .then(setAutoLockState)
                        .catch((error) => toast(errText(error), "warn"));
                    }}
                  >
                    {AUTO_LOCK_CHOICES.map((m) => (
                      <option key={m} value={m}>
                        {autoLockLabel(m)}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>
          </div>

          {/* Connected sites */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="globe" size={16} /> {t("settings.connectedSites")}
              </h2>
              <p>{t("settings.connectedSitesHint")}</p>
            </div>
            <div className="set-card">
              {connectedSites.length === 0 ? (
                <div className="set-row">
                  <div className="gr">
                    <div className="rs">{t("settings.connectedSitesEmpty")}</div>
                  </div>
                </div>
              ) : (
                connectedSites.map((origin) => (
                  <div className="set-row" key={origin}>
                    <div className="gr">
                      <div className="rl connected-site" title={origin}>
                        {origin.replace(/^https?:\/\//, "")}
                      </div>
                    </div>
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() =>
                        void disconnectSite(origin)
                          .then(setConnectedSites)
                          .catch((error) => toast(errText(error), "warn"))
                      }
                    >
                      {t("settings.disconnect")}
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>

          {/* About */}
          <div className="set-group">
            <div className="set-group-head">
              <h2>
                <Icon name="info" size={16} /> {t("settings.about")}
              </h2>
            </div>
            <div className="set-card">
              <div className="about-card">
                <img className="about-mark" src={logoMark} alt="" />
                <div className="about-meta">
                  <div className="about-name">AutoDesktop</div>
                  <div className="about-tag">{t("settings.tagline")}</div>
                  {updated ? (
                    <div className="up-to-date">
                      <Icon name="check" size={13} /> {t("settings.upToDate")}
                    </div>
                  ) : updateInfo?.available ? (
                    <div className="update-available">
                      <Icon name="download" size={13} />{" "}
                      {t("settings.updateAvailable", {
                        version: updateInfo.latestVersion,
                      })}
                    </div>
                  ) : (
                    <div className="about-ver">
                      {t("settings.version")} {APP_VERSION}
                    </div>
                  )}
                </div>
                {!(updateInfo?.available && updateInfo.manual) && (
                  <button
                    className="btn btn-ghost btn-sm"
                    disabled={checkingUpdate}
                    onClick={() => void handleCheckUpdates()}
                  >
                    {updateButtonLabel}
                  </button>
                )}
              </div>
              {updateProgress && updateBar && (
                <div className="update-progress">
                  <div className="update-progress-meta">
                    <span>
                      {updateProgress.phase === "installing"
                        ? t("settings.installingUpdate")
                        : t("settings.downloadingUpdate")}
                    </span>
                    {!updateBar.indeterminate && (
                      <span>{updateBar.percent}%</span>
                    )}
                  </div>
                  <div
                    className="update-progress-track"
                    role="progressbar"
                    aria-valuemin={0}
                    aria-valuemax={100}
                    aria-valuenow={updateBar.percent ?? undefined}
                  >
                    <div
                      className={
                        updateBar.indeterminate
                          ? "update-progress-fill indeterminate"
                          : "update-progress-fill"
                      }
                      style={
                        updateBar.indeterminate
                          ? undefined
                          : { width: `${updateBar.percent}%` }
                      }
                    />
                  </div>
                </div>
              )}
              {updateInfo?.available &&
                updateInfo.manual &&
                !checkingUpdate && (
                  <div className="update-manual-actions">
                    <button
                      className="btn btn-ghost btn-sm"
                      onClick={() => void handleInstallUpdate()}
                    >
                      {t("settings.retryAutoUpdate")}
                    </button>
                    <button
                      className="btn btn-primary btn-sm"
                      onClick={() => void handleManualDownload()}
                    >
                      {t("settings.manualDownload")}
                    </button>
                  </div>
                )}
            </div>
          </div>
        </div>
      </div>
    </>
  );
}

function ExportSecretModal({
  wallet,
  t,
  onClose,
}: {
  wallet: WalletInfo;
  t: TFn;
  onClose: () => void;
}) {
  const [password, setPassword] = useState("");
  const [secret, setSecret] = useState<ExportedSecret | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const isPhrase = wallet.kind === "hd";
  const title = isPhrase
    ? t("settings.exportPhraseTitle")
    : t("settings.exportPrivateKeyTitle");

  async function reveal() {
    if (!password) return;
    setBusy(true);
    setError(null);
    try {
      const out = await exportWalletSecret(wallet.id, password);
      setSecret(out);
      setPassword("");
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="scrim" onClick={onClose}>
      <div className="modal export-secret-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{title}</div>
          <button className="icon-btn bare" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          <div className="export-warning">
            <Icon name="shield" size={16} />
            <span>{t("settings.exportSecretWarning")}</span>
          </div>
          <div className="export-wallet-name">
            {wallet.label} · {wallet.accounts[0] ?? ""}
          </div>

          {!secret ? (
            <>
              <div className="field">
                <label className="field-label">{t("lock.password")}</label>
                <input
                  className="input"
                  type="password"
                  value={password}
                  autoFocus
                  placeholder={t("lock.password")}
                  onChange={(e) => {
                    setPassword(e.target.value);
                    setError(null);
                  }}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void reveal();
                  }}
                />
              </div>
              {error && <div className="form-error">{error}</div>}
              <div className="modal-actions">
                <button className="btn btn-ghost" onClick={onClose}>
                  {t("wallet.cancel")}
                </button>
                <button
                  className="btn btn-danger"
                  disabled={busy || !password}
                  onClick={() => void reveal()}
                >
                  {busy ? "..." : t("settings.revealSecret")}
                </button>
              </div>
            </>
          ) : (
            <>
              {isPhrase ? (
                <ol className="export-phrase-grid">
                  {secret.secret.split(/\s+/).map((word, index) => (
                    <li key={`${word}-${index}`}>
                      <span>{index + 1}</span>
                      <strong>{word}</strong>
                    </li>
                  ))}
                </ol>
              ) : (
                <div className="export-key-box">{secret.secret}</div>
              )}
              <div className="modal-actions">
                <button className="btn btn-ghost" onClick={onClose}>
                  {t("wallet.cancel")}
                </button>
                <CopyButton
                  className="btn btn-primary"
                  size={15}
                  value={secret.secret}
                  onCopied={() => toast(t("settings.secretCopied"))}
                >
                  {t("wallet.copy")}
                </CopyButton>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// Add / edit a network. `initial === null` = add a custom network; otherwise edit
// (the chain id + built-in flag are fixed for an existing network).
function NetworkForm({
  t,
  initial,
  onClose,
}: {
  t: TFn;
  initial: Chain | null;
  onClose: () => void;
}) {
  const editing = initial !== null;
  const [name, setName] = useState(initial?.name ?? "");
  const [id, setId] = useState(initial?.id ?? "");
  const [symbol, setSymbol] = useState(initial?.symbol ?? "ETH");
  const [rpc, setRpc] = useState(initial?.rpc ?? "");
  const [explorerUrl, setExplorerUrl] = useState(initial?.explorerUrl ?? "");
  const [decimals, setDecimals] = useState(String(initial?.decimals ?? 18));
  const [color, setColor] = useState(initial?.color ?? "#5b4bf0");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const { cls, close } = useModalExit(onClose);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) close();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [busy, close]);

  async function submit() {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const base = {
        id: id.trim(),
        name: name.trim(),
        symbol: symbol.trim() || "ETH",
        rpc: rpc.trim(),
        explorerUrl: explorerUrl.trim() || undefined,
        decimals: parseInt(decimals, 10) || 18,
        color,
      };
      if (editing) await updateChain({ ...base, builtin: initial.builtin });
      else await addChain(base);
      close();
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  }

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={() => !busy && close()}>
      <form
        className={`modal network-modal t-modal ${cls}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="network-modal-title"
        onClick={(event) => event.stopPropagation()}
        onSubmit={(event) => {
          event.preventDefault();
          void submit();
        }}
      >
        <div className="modal-head">
          <div className="modal-title" id="network-modal-title">
            {editing ? t("settings.editNetwork") : t("settings.addNetwork")}
          </div>
          <button
            className="icon-btn bare"
            type="button"
            aria-label={t("settings.cancel")}
            disabled={busy}
            onClick={close}
          >
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body scroll">
          <div className="net-grid">
            <div className="field net-wide">
              <label className="field-label">{t("settings.netName")}</label>
              <div className="net-name-row">
                <input
                  type="color"
                  className="net-color"
                  value={color}
                  onChange={(e) => setColor(e.target.value)}
                />
                <input
                  className="input"
                  autoFocus
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="My Network"
                />
              </div>
            </div>
            <div className="field">
              <label className="field-label">{t("settings.netChainId")}</label>
              <input
                className="input mono"
                value={id}
                onChange={(e) => setId(e.target.value)}
                placeholder="0x… or 1234"
                disabled={editing}
              />
            </div>
            <div className="field">
              <label className="field-label">{t("settings.netSymbol")}</label>
              <input
                className="input"
                value={symbol}
                onChange={(e) => setSymbol(e.target.value)}
                placeholder="ETH"
              />
            </div>
            <div className="field net-wide">
              <label className="field-label">{t("settings.netRpc")}</label>
              <input
                className="input mono"
                value={rpc}
                onChange={(e) => setRpc(e.target.value)}
                placeholder="https://…"
              />
            </div>
            <div className="field net-wide">
              <label className="field-label">{t("settings.netExplorer")}</label>
              <input
                className="input mono"
                value={explorerUrl}
                onChange={(e) => setExplorerUrl(e.target.value)}
                placeholder="https://etherscan.io/tx/"
              />
            </div>
            <div className="field">
              <label className="field-label">{t("settings.netDecimals")}</label>
              <input
                className="input mono"
                value={decimals}
                onChange={(e) => setDecimals(e.target.value)}
                placeholder="18"
              />
            </div>
          </div>
          {error && <div className="net-error">{error}</div>}
          <div className="net-acts">
            <button
              className="btn btn-ghost btn-sm"
              type="button"
              disabled={busy}
              onClick={close}
            >
              {t("settings.cancel")}
            </button>
            <button
              className="btn btn-primary btn-sm"
              type="submit"
              disabled={busy || !name || !id}
            >
              {busy ? "…" : t("settings.save")}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
