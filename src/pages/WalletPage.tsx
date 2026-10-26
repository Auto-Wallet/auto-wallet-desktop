import { Fragment, useEffect, useMemo, useState } from "react";
import "./WalletPage.css";
import { chainLogo, findChain, useChains, type Chain } from "../lib/chains";
import { filterChains } from "../lib/chainSearch";
import {
  loadActivity,
  replaceActivityTransaction,
  syncActivityReceipts,
  useActivity,
  type ActivityRecord,
} from "../lib/activity";
import { isTauri, openExternalUrl } from "../lib/platform";
import { explorerTokenUrl, explorerTxUrl, txExplorerUrl } from "../lib/explorer";
import { ChainIcon } from "../lib/ChainIcon";
import {
  useDefiPositions,
  type DefiState,
} from "../lib/defi";
import { summarizePortfolio } from "../lib/portfolioSummary";
import {
  fmtAmount,
  fmtPct,
  fmtUsd,
  formatUnits,
  fmtUnitsDisplay,
  isAddress,
  parseUnits,
  shortAddress,
  toHexQuantity,
  weiToUsd,
} from "../lib/format";
import {
  addVaultAccount,
  createVault,
  deleteWallet,
  importPrivateKey,
  importVault,
  onRequestPhase,
  renameWallet,
  useVault,
  walletSend,
  type RequestPhase,
  type WalletInfo,
} from "../lib/vault";
import { LedgerList, useLedgerScan } from "../lib/LedgerPicker";
import { WalletNameField } from "../lib/WalletNameField";
import {
  useDropdown,
  useHoverGroup,
  useModalExit,
  useSegPill,
  useSpin,
  useToggleInit,
} from "../lib/transitions";
import {
  addWatchAccount,
  removeWatchAccount,
  renameWatchAccount,
  setActive,
  useAccounts,
  useActiveAccount,
  type Account,
} from "../lib/accounts";
import { useBalances, type BalanceState } from "../lib/useBalances";
import {
  usePrices,
  useTokenPrices,
  tkPriceKey,
  priceForChainAsset,
  type Price,
  type PriceState,
  type PricedToken,
} from "../lib/prices";
import {
  usePortfolioHistory,
  type PortfolioTrend,
  type TrendExtreme,
} from "../lib/portfolioHistory";
import {
  fetchAllQuotes,
  getProvider,
  isNativeAddress,
  loadSupportedSets,
  pickBestSlot,
  PROVIDERS,
  NATIVE_TOKEN_ADDRESS,
  type MergedChain,
  type MergedToken,
  type NeutralStatus,
  type ProviderId,
  type ProviderToken,
  type QuoteParams,
  type QuoteSlot,
} from "../lib/swap";
import {
  addCustomToken,
  encodeErc20Transfer,
  fetchTokenMeta,
  isCustomToken,
  removeCustomToken,
  tokenKey,
  tokensForChain,
  useCustomTokens,
  useTokenBalances,
  type CustomStore,
  type TokenBalance,
  type TokenMeta,
} from "../lib/tokens";
import { localeTag, useT, type Lang, type TFn } from "../lib/i18n";
import { Icon, type IconName } from "../lib/icons";
import { Avatar, CopyButton } from "../lib/ui";
import { askConfirm } from "../lib/confirm";
import { QrCode } from "../lib/qr";
import { toast } from "../lib/toast";
import { rpc } from "../lib/rpc";
import { SwapFeeBreakdown } from "./SwapFeeBreakdown";
import { accountMenuClosesOnKey } from "./accountMenuKeys";
import { SafeQueue } from "../SafeQueue";
import {
  addSafeAccount,
  defaultSafeServiceUrl,
  inspectSafe,
  removeSafeAccount,
  renameSafeAccount,
  useSafes,
  type ImportedSafe,
  type SafeInfo,
} from "../lib/safes";

const PINNED_ACCOUNT_STORAGE_KEY = "autodesktop:pinned-wallet-addresses";
const DEFI_ENABLED_ACCOUNT_STORAGE_KEY = "autodesktop:defi-enabled-wallet-addresses";

function loadPinnedAccounts(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(
      window.localStorage.getItem(PINNED_ACCOUNT_STORAGE_KEY) ?? "[]",
    );
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.toLowerCase());
  } catch {
    return [];
  }
}

function savePinnedAccounts(addresses: string[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(
    PINNED_ACCOUNT_STORAGE_KEY,
    JSON.stringify(addresses),
  );
}

function loadDefiEnabledAccounts(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const parsed = JSON.parse(
      window.localStorage.getItem(DEFI_ENABLED_ACCOUNT_STORAGE_KEY) ?? "[]",
    );
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((v): v is string => typeof v === "string")
      .map((v) => v.toLowerCase());
  } catch {
    return [];
  }
}

function saveDefiEnabledAccounts(addresses: string[]) {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(
    DEFI_ENABLED_ACCOUNT_STORAGE_KEY,
    JSON.stringify(addresses),
  );
}

// Wallet page (VISION ①). Aurora portfolio: account/wallet switcher (create/import/
// link + rename/delete), hero with a REAL total (native balances × price-oracle
// prices), quick actions, a per-chain native token list with USD, and an honest
// "coming soon" for activity. No fabricated holdings — failed prices/balances
// surface as explicit states.
export default function WalletPage() {
  const { t, lang } = useT();
  const chains = useChains();
  const chainIds = useMemo(() => chains.map((c) => c.id), [chains]);
  const active = useActiveAccount();
  const custom = useCustomTokens();
  const { balances, balancesAddress, refresh } = useBalances(active.address);
  const {
    tokenBalances,
    tokenBalancesAddress,
    refreshTokens,
    holdings,
  } = useTokenBalances(
    active.address,
    chainIds,
  );
  const { state: prices, refresh: refreshPrices } = usePrices(
    chains.map((c) => c.symbol),
  );
  const activity = useActivity();

  // Price only the ERC-20s actually held (>0); unmapped/unknown ones get no USD.
  const pricedTokens = useMemo<PricedToken[]>(() => {
    const out: PricedToken[] = [];
    for (const c of chains) {
      for (const tk of tokensForChain(custom, c.id)) {
        const st = tokenBalances[tokenKey(c.id, tk.address)];
        if (st?.status === "ok" && BigInt(st.wei) > 0n)
          out.push({ chainId: c.id, address: tk.address, symbol: tk.symbol });
      }
    }
    return out;
  }, [chains, custom, tokenBalances]);
  const { state: tokenPriceState, refresh: refreshTokenPrices } =
    useTokenPrices(pricedTokens);
  const tokenPrices = tokenPriceState.prices;

  const [tab, setTab] = useState<"tokens" | "activity">("tokens");
  const holdingsSegRef = useSegPill<HTMLDivElement>(tab);
  const heroActions = useHoverGroup<HTMLDivElement>();
  const refreshSpin = useSpin<HTMLSpanElement>();
  const [filter, setFilter] = useState<string>("all");
  const [chainMenuOpen, setChainMenuOpen] = useState(false);
  const chainMenu = useDropdown(chainMenuOpen);
  const [chainQuery, setChainQuery] = useState("");
  const [showReceive, setShowReceive] = useState(false);
  const [showAddToken, setShowAddToken] = useState(false);
  const [showSend, setShowSend] = useState(false);
  const [showBridge, setShowBridge] = useState(false);
  const [selectedTokenKey, setSelectedTokenKey] = useState<string | null>(null);
  const [tokenSearch, setTokenSearch] = useState("");
  const [showZeroTokenBalances, setShowZeroTokenBalances] = useState(false);
  const [replaceTarget, setReplaceTarget] = useState<{
    record: ActivityRecord;
    action: "speedup" | "cancel";
  } | null>(null);
  const [sendAssetKey, setSendAssetKey] = useState<string | undefined>(
    undefined,
  );
  const [bridgeAssetKey, setBridgeAssetKey] = useState<string | undefined>(
    undefined,
  );
  const [defiEnabledAddresses, setDefiEnabledAddresses] = useState<string[]>(
    loadDefiEnabledAccounts,
  );

  const isWatch = active.kind === "watch";
  const isSafe = active.kind === "safe";
  const activeAddressKey = active.address.toLowerCase();
  const defiEnabled = defiEnabledAddresses.includes(activeAddressKey);
  const accountActivity = useMemo(
    () =>
      activity.filter(
        (a) => a.from.toLowerCase() === active.address.toLowerCase(),
      ),
    [activity, active.address],
  );

  useEffect(() => {
    void loadActivity();
  }, []);

  // Assets the active account can actually send (non-zero native + ERC-20).
  const sendableAssets = useMemo<SendAsset[]>(() => {
    const out: SendAsset[] = [];
    for (const c of chains) {
      const nb = balances[c.id];
      if (nb?.status === "ok" && BigInt(nb.wei) > 0n) {
        out.push({
          key: `n:${c.id}`,
          chainId: c.id,
          chainName: c.name,
          kind: "native",
          symbol: c.symbol,
          decimals: c.decimals,
          color: c.color,
          logo: chainLogo(c.id),
          wei: nb.wei,
        });
      }
      for (const tk of tokensForChain(custom, c.id)) {
        const st = tokenBalances[tokenKey(c.id, tk.address)];
        if (st?.status === "ok" && BigInt(st.wei) > 0n) {
          out.push({
            key: `e:${c.id}:${tk.address}`,
            chainId: c.id,
            chainName: c.name,
            kind: "erc20",
            symbol: tk.symbol,
            decimals: tk.decimals,
            address: tk.address,
            color: seedColor(tk.address),
            logo: tk.logo || undefined,
            wei: st.wei,
          });
        }
      }
    }
    return out;
  }, [chains, balances, tokenBalances, custom]);

  // Build every chain's rows once. The hero TOTAL is always the sum across ALL
  // chains; the network filter below only narrows the visible token LIST, it must
  // not change the total.
  const allRows = useMemo(
    () =>
      buildRows(chains, custom, balances, tokenBalances, prices, tokenPrices, {
        includeZeroDefaultTokens: false,
      }),
    [chains, custom, balances, tokenBalances, prices, tokenPrices],
  );
  const tokenListRows = useMemo(
    () =>
      buildRows(chains, custom, balances, tokenBalances, prices, tokenPrices, {
        includeZeroDefaultTokens: true,
      }),
    [chains, custom, balances, tokenBalances, prices, tokenPrices],
  );
  const selectedToken = useMemo(
    () => tokenListRows.find((row) => row.key === selectedTokenKey) ?? null,
    [tokenListRows, selectedTokenKey],
  );
  const walletAssetsOverOneUsd = useMemo(
    () => computeWalletAssetsOverOneUsd(allRows, prices.status === "loading"),
    [allRows, prices.status],
  );
  const defi = useDefiPositions(
    active.address,
    walletAssetsOverOneUsd,
    defiEnabled,
  );
  const rows = useMemo(
    () =>
      filter === "all"
        ? tokenListRows
        : tokenListRows.filter((r) => r.chainId === filter),
    [tokenListRows, filter],
  );
  const searchedRows = useMemo(
    () => filterTokenRows(rows, tokenSearch),
    [rows, tokenSearch],
  );
  // Chains matching the search are HIGHLIGHTED in the network filter (never
  // filtered out — the pills stay in place so the layout doesn't jump).
  const highlightedChainIds = useMemo(() => {
    const q = normalizedSearch(tokenSearch);
    if (!q) return new Set<string>();
    return new Set(
      chains
        .filter((c) => includesQuery(q, [c.name, c.symbol]))
        .map((c) => c.id),
    );
  }, [chains, tokenSearch]);
  // Network filter menu: chains with actual holdings float to the top so the
  // useful ones are one click away; the rest stay searchable, not plastered
  // across the page as a wall of pills.
  const chainMenuChains = useMemo(() => {
    const withAssets = new Set(tokenListRows.map((r) => r.chainId));
    return filterChains(chains, chainQuery).sort(
      (a, b) =>
        Number(withAssets.has(b.id)) - Number(withAssets.has(a.id)) ||
        a.name.localeCompare(b.name),
    );
  }, [chains, chainQuery, tokenListRows]);
  const filterChain =
    filter === "all" ? null : (chains.find((c) => c.id === filter) ?? null);
  useEffect(() => {
    if (!chainMenuOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setChainMenuOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [chainMenuOpen]);
  const hiddenZeroTokenCount = useMemo(
    () => searchedRows.filter(isZeroBalanceRow).length,
    [searchedRows],
  );
  const visibleRows = useMemo(
    () =>
      showZeroTokenBalances
        ? searchedRows
        : searchedRows.filter((row) => !isZeroBalanceRow(row)),
    [searchedRows, showZeroTokenBalances],
  );
  const portfolio = useMemo(
    () =>
      summarizePortfolio({
        accountCurrent:
          balancesAddress === active.address &&
          tokenBalancesAddress === active.address,
        assets: allRows.map((row) => ({
          balance: row.state,
          decimals: row.decimals,
          price: row.price,
          priceSource: row.kind === "native" ? "native" : "token",
        })),
        tokenBalanceStates: holdings.map(
          (holding) => tokenBalances[tokenKey(holding.chainId, holding.address)],
        ),
        nativePriceStatus: prices.status,
        tokenPriceStatus: tokenPriceState.status,
        defi: {
          enabled: defiEnabled,
          status: defi.status,
          totalUsd: defi.positions.reduce(
            (sum, position) => sum + position.balanceUsd,
            0,
          ),
        },
      }),
    [
      active.address,
      allRows,
      balancesAddress,
      defi.positions,
      defi.status,
      defiEnabled,
      holdings,
      prices.status,
      tokenBalances,
      tokenBalancesAddress,
      tokenPriceState.status,
    ],
  );
  // Every snapshot has to be comparable to every other one, or the chart draws
  // crashes that never happened. Only the same complete state that may paint an
  // exact total may enter history; loading and partial failures both stay out.
  const totalPending = portfolio.status !== "ready";
  const trend = usePortfolioHistory(active.address, portfolio.total, totalPending);
  const trendPercent = trend.percent;

  function refreshAll() {
    refreshSpin.spin();
    refresh();
    refreshTokens();
    refreshPrices();
    refreshTokenPrices();
    if (defiEnabled) void defi.refresh(true);
    toast(t("common.refreshed"));
  }

  function setDefiEnabled(enabled: boolean) {
    setDefiEnabledAddresses((prev) => {
      const withoutActive = prev.filter(
        (address) => address !== activeAddressKey,
      );
      const next = enabled ? [...withoutActive, activeAddressKey] : withoutActive;
      saveDefiEnabledAccounts(next);
      return next;
    });
  }

  // Deleting a reading is the outermost layer of this action, so it is where a
  // failure gets reported — the history is on disk and the write can fail.
  async function removeTrendPoint(timestamp: number) {
    try {
      await trend.remove(timestamp);
      toast(t("wallet.trendPointRemoved"));
    } catch (e) {
      toast(errText(e), "warn");
    }
  }

  useEffect(() => {
    void trend.recordNow();
  }, [active.address, portfolio.total, totalPending]);

  useEffect(() => {
    const id = window.setInterval(() => {
      refreshAll();
      window.setTimeout(() => void trend.recordNow(), 20 * 1000);
    }, 60 * 60 * 1000);
    return () => {
      window.clearInterval(id);
    };
  }, [
    refresh,
    refreshTokens,
    refreshPrices,
    refreshTokenPrices,
    defi.refresh,
    defiEnabled,
    trend.recordNow,
  ]);

  return (
    <div className="page scroll">
      <div className="wallet-pad">
        {/* Account header row — aligned with the hero's left edge; copy sits next
            to the wallet switcher. */}
        <div className="wallet-head">
          <AccountSwitcher />
          <CopyButton
            className="icon-btn"
            title={t("wallet.copy")}
            size={17}
            value={active.address}
            onCopied={() => toast(t("common.copied"))}
          />
        </div>

        {/* Portfolio hero — balance, trend and the primary actions as ONE visual
            unit (previously a gradient card plus separate floating action tiles,
            which read as disconnected patches). */}
        <div className="wallet-top">
          <div className="hero">
            {/* Sits OUTSIDE .hero-row on purpose: the chart is absolutely
                positioned and .hero-row is `position: relative`, so nesting it
                there caps its height at the balance block (~100px) instead of
                the card. That is what collapsed it to nothing in v0.2.39. */}
            <PortfolioSparkline
              trend={trend}
              onRemove={(timestamp) => void removeTrendPoint(timestamp)}
            />
            <div className="hero-row">
              <div className="hero-main">
                <div className="hero-label">
                  <Icon name="wallet" size={15} /> {t("wallet.total")} ·{" "}
                  {active.label}
                </div>
                {portfolio.status === "loading" ? (
                  <div className="hero-skel" />
                ) : portfolio.status === "ready" || portfolio.status === "partial" ? (
                  <>
                    <div className="hero-total disp tnum">
                      <HeroAmount
                        n={portfolio.total}
                        approximate={portfolio.status === "partial"}
                      />
                    </div>
                    {portfolio.status === "ready" ? (
                      <div className="hero-change">
                        <span className="pill">
                          <Icon
                            name={(trendPercent ?? 0) >= 0 ? "arrowUp" : "arrowDown"}
                            size={13}
                          />
                          {trendPercent == null
                            ? t("wallet.trendCollecting")
                            : fmtPct(trendPercent)}
                        </span>
                        <span style={{ opacity: 0.9 }}>· {trend.label}</span>
                      </div>
                    ) : (
                      <div className="hero-note">
                        <Icon name="info" size={13} /> {t("wallet.totalPartial")}
                      </div>
                    )}
                  </>
                ) : (
                  <>
                    <div className="hero-total disp tnum">$—</div>
                    <div className="hero-note">
                      <Icon name="info" size={13} />{" "}
                      {t("wallet.totalIncomplete")}
                    </div>
                  </>
                )}
              </div>
              {/* Refresh balances + prices (the eye/hide-balance toggle was dropped). */}
              <button
                className="hero-eye"
                onClick={refreshAll}
                title={t("wallet.refresh")}
              >
                <span className="t-spin" ref={refreshSpin.ref}>
                  <Icon name="refresh" size={17} />
                </span>
              </button>
            </div>
            {!isWatch && (
              // Indices must match DOM order — the comb measures distance off
              // the rendered .t-avatar list, and Send/Swap drop out for Safe.
              <div className="hero-actions" {...heroActions.group}>
                <HeroAction
                  icon="receive"
                  label={t("wallet.receive")}
                  onClick={() => setShowReceive(true)}
                  hover={heroActions.item(0)}
                />
                {!isSafe && (
                  <>
                    <HeroAction
                      icon="send"
                      label={t("wallet.send")}
                      onClick={() => {
                        setSendAssetKey(undefined);
                        setShowSend(true);
                      }}
                      hover={heroActions.item(1)}
                    />
                    <HeroAction
                      icon="bridge"
                      label={t("wallet.swap")}
                      onClick={() => {
                        setBridgeAssetKey(undefined);
                        setShowBridge(true);
                      }}
                      hover={heroActions.item(2)}
                    />
                  </>
                )}
              </div>
            )}
          </div>
          {isWatch && (
            <div className="card watch-banner">
              <Icon name="eye" size={18} /> {t("wallet.watchOnly")}
            </div>
          )}
          {isSafe && (
            <div className="card watch-banner safe-banner">
              <Icon name="shield" size={18} /> {t("safe.manualSigning")}
            </div>
          )}
        </div>

        {isSafe && <SafeQueue address={active.address} />}

        {/* Tokens / Activity */}
        <div className="holdings">
          <div className="holdings-head">
            <div className="seg" ref={holdingsSegRef}>
              <span className="t-tabs-pill" aria-hidden="true" />
              <button
                className={tab === "tokens" ? "on" : ""}
                onClick={() => setTab("tokens")}
              >
                {t("wallet.tokens")}
              </button>
              <button
                className={tab === "activity" ? "on" : ""}
                onClick={() => setTab("activity")}
              >
                {t("wallet.activity")}
              </button>
            </div>
            {tab === "tokens" && (
              <div className="holdings-search">
                <SectionSearch
                  value={tokenSearch}
                  onChange={setTokenSearch}
                  placeholder={t("wallet.searchTokenHoldings")}
                />
              </div>
            )}
          </div>

          {tab === "tokens" ? (
            <>
              <div className="chain-filter">
                <div className="cf-select">
                  <button
                    className={`cf-select-btn${filterChain ? " on" : ""}${
                      highlightedChainIds.size > 0 ? " hl" : ""
                    }`}
                    onClick={() => {
                      setChainQuery("");
                      setChainMenuOpen((o) => !o);
                    }}
                  >
                    {filterChain ? (
                      <ChainIcon chain={filterChain} size={15} />
                    ) : (
                      <Icon name="globe" size={15} />
                    )}
                    <span className="cf-select-label">
                      {filterChain ? filterChain.name : t("wallet.allNetworks")}
                    </span>
                    <Icon name="chevronD" size={14} />
                  </button>
                  {chainMenu.mounted && (
                    <>
                      <div
                        className="cf-scrim"
                        onClick={() => setChainMenuOpen(false)}
                      />
                      <div className={`cf-menu scroll t-dropdown ${chainMenu.cls}`}>
                        <label className="cf-search">
                          <Icon name="search" size={14} />
                          <input
                            value={chainQuery}
                            onChange={(e) => setChainQuery(e.target.value)}
                            placeholder={t("browser.searchNetworks")}
                            autoComplete="off"
                            autoFocus
                          />
                        </label>
                        <ChainFilterOptions
                          t={t}
                          chains={chainMenuChains}
                          query={chainQuery}
                          filter={filter}
                          highlightedChainIds={highlightedChainIds}
                          onPick={(id) => {
                            setFilter(id);
                            setChainMenuOpen(false);
                          }}
                        />
                      </div>
                    </>
                  )}
                </div>
              </div>
              <section className="asset-section">
                <div className="asset-section-head">
                  <div>
                    <div className="asset-section-title">
                      {t("wallet.tokenHoldings")}
                    </div>
                    <div className="asset-section-sub">
                      {t("wallet.tokenHoldingsHint")}
                    </div>
                  </div>
                </div>
                {visibleRows.length > 0 ? (
                  <div className="token-list">
                    {visibleRows.map((r) => (
                      <HoldingRow
                        key={r.key}
                        row={r}
                        t={t}
                        canSign={!!active.signer}
                        onOpen={() => setSelectedTokenKey(r.key)}
                        onRetry={refreshAll}
                        onSend={(assetKey) => {
                          setSendAssetKey(assetKey);
                          setShowSend(true);
                        }}
                        onSwap={(assetKey) => {
                          setBridgeAssetKey(assetKey);
                          setShowBridge(true);
                        }}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="section-empty">{t("wallet.noTokenMatches")}</div>
                )}
                {(showZeroTokenBalances || hiddenZeroTokenCount > 0) && (
                  <button
                    type="button"
                    className="zero-token-toggle"
                    onClick={() => setShowZeroTokenBalances((show) => !show)}
                  >
                    {showZeroTokenBalances
                      ? t("wallet.hideZeroTokens")
                      : t("wallet.showZeroTokens", {
                          count: hiddenZeroTokenCount,
                        })}
                  </button>
                )}
                <button
                  className="add-token"
                  onClick={() => setShowAddToken(true)}
                >
                  <Icon name="plus" size={16} /> {t("wallet.addToken")}
                </button>
              </section>
              <DefiSection
                t={t}
                defi={defi}
                enabled={defiEnabled}
                onEnabledChange={setDefiEnabled}
              />
            </>
          ) : (
            <ActivityList
              records={accountActivity}
              chains={chains}
              t={t}
              lang={lang}
              onReplace={(record, action) => setReplaceTarget({ record, action })}
            />
          )}
        </div>
      </div>

      {selectedToken && (
        <TokenDetailModal
          row={selectedToken}
          canSign={!!active.signer}
          onClose={() => setSelectedTokenKey(null)}
          onReceive={() => {
            setSelectedTokenKey(null);
            setShowReceive(true);
          }}
          onSend={(assetKey) => {
            setSelectedTokenKey(null);
            setSendAssetKey(assetKey);
            setShowSend(true);
          }}
          onSwap={(assetKey) => {
            setSelectedTokenKey(null);
            setBridgeAssetKey(assetKey);
            setShowBridge(true);
          }}
        />
      )}
      {showReceive && (
        <ReceiveModal account={active} onClose={() => setShowReceive(false)} />
      )}
      {showAddToken && (
        <AddTokenModal
          defaultChain={filter !== "all" ? filter : undefined}
          onClose={() => setShowAddToken(false)}
        />
      )}
      {showSend && (
        <SendModal
          assets={sendableAssets}
          initialAssetKey={sendAssetKey}
          onClose={() => setShowSend(false)}
        />
      )}
      {showBridge && (
        <CrossChainModal
          assets={sendableAssets}
          initialAssetKey={bridgeAssetKey}
          activeAddress={active.address}
          onClose={() => setShowBridge(false)}
        />
      )}
      {replaceTarget && (
        <ReplaceTxModal
          record={replaceTarget.record}
          action={replaceTarget.action}
          t={t}
          onClose={() => setReplaceTarget(null)}
          onSubmit={async (maxFee, priorityFee) => {
            await replaceActivityTransaction(
              replaceTarget.record.id,
              replaceTarget.action,
              maxFee,
              priorityFee,
            );
            setReplaceTarget(null);
            await syncActivityReceipts().catch(() => undefined);
          }}
        />
      )}
    </div>
  );
}

function SectionSearch({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <label className="section-search">
      <Icon name="search" size={14} />
      <input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {value && (
        <button type="button" onClick={() => onChange("")} aria-label="Clear">
          <Icon name="close" size={13} />
        </button>
      )}
    </label>
  );
}

export function ChainFilterOptions({
  t,
  chains,
  query,
  filter,
  highlightedChainIds,
  onPick,
}: {
  t: TFn;
  chains: Chain[];
  query: string;
  filter: string;
  highlightedChainIds: Set<string>;
  onPick: (id: string) => void;
}) {
  return (
    <>
      <button
        className={`cf-item${filter === "all" ? " on" : ""}`}
        onClick={() => onPick("all")}
      >
        <span className="cf-item-ic">
          <Icon name="globe" size={15} />
        </span>
        <span className="cf-item-name">{t("wallet.allNetworks")}</span>
        {filter === "all" && <Icon name="check" size={15} />}
      </button>
      {chains.map((c) => (
        <button
          key={c.id}
          className={`cf-item${filter === c.id ? " on" : ""}${
            highlightedChainIds.has(c.id) ? " hl" : ""
          }`}
          onClick={() => onPick(c.id)}
        >
          <span className="cf-item-ic">
            <ChainIcon chain={c} size={16} />
          </span>
          <span className="cf-item-name">{c.name}</span>
          {filter === c.id && <Icon name="check" size={15} />}
        </button>
      ))}
      {chains.length === 0 && query.trim() !== "" && (
        <div className="cf-empty">{t("wallet.noNetworkMatches")}</div>
      )}
    </>
  );
}

export function DefiSection({
  t,
  defi,
  enabled,
  onEnabledChange,
}: {
  t: TFn;
  defi: DefiState;
  enabled: boolean;
  onEnabledChange: (enabled: boolean) => void;
}) {
  const [query, setQuery] = useState("");
  const [showSmallPositions, setShowSmallPositions] = useState(false);
  const defiToggle = useToggleInit(enabled);
  const positions = useMemo(
    () => filterDefiPositions(defi.positions, query),
    [defi.positions, query],
  );
  const smallPricedPositions = useMemo(
    () => positions.filter(isSmallPricedDefiPosition),
    [positions],
  );
  const visiblePositions = useMemo(
    () =>
      showSmallPositions
        ? positions
        : positions.filter((position) => !isSmallPricedDefiPosition(position)),
    [positions, showSmallPositions],
  );
  const hiddenSmallPositionCount = smallPricedPositions.length;
  const isRefreshing = defi.status === "loading" && defi.positions.length > 0;
  return (
    <section className="asset-section defi-section" aria-busy={isRefreshing}>
      <div className="asset-section-head">
        <div>
          <div className="asset-section-title">{t("wallet.defiHoldings")}</div>
          <div className="asset-section-sub">
            {t("wallet.defiHoldingsHint")}
            {defi.source ? ` · Source: ${defi.source}` : ""}
          </div>
        </div>
        <div className="asset-section-tools">
          <div className="defi-toggle-label">
            <span>{t("wallet.defiEnabled")}</span>
            <button
              type="button"
              className={`toggle t-toggle${defiToggle.initCls}${enabled ? " on" : ""}`}
              data-on={defiToggle.dataOn}
              role="switch"
              aria-checked={enabled}
              aria-label={t("wallet.defiEnabled")}
              title={enabled ? t("wallet.defiDisable") : t("wallet.defiEnable")}
              onClick={() => onEnabledChange(!enabled)}
            >
              <i className="t-toggle-thumb" />
            </button>
          </div>
          {enabled && isRefreshing && (
            <span className="section-refreshing">
              <Icon name="refresh" size={13} />
              {t("wallet.refreshingDefi")}
            </span>
          )}
          {enabled && (
            <SectionSearch
              value={query}
              onChange={setQuery}
              placeholder={t("wallet.searchDefiPositions")}
            />
          )}
        </div>
      </div>
      {!enabled ? (
        <div className="defi-empty">
          <div className="defi-empty-ic">
            <Icon name="bridge" size={18} />
          </div>
          <div>
            <div className="defi-empty-title">{t("wallet.defiDisabled")}</div>
            <div className="defi-empty-sub">{t("wallet.defiDisabledHint")}</div>
          </div>
        </div>
      ) : defi.status === "loading" && defi.positions.length === 0 ? (
        <div className="defi-list">
          <div className="defi-card">
            <div className="defi-card-head">
              <span
                className="skeleton"
                style={{ width: 38, height: 38, gridRow: "1 / -1" }}
              />
              <span className="skeleton" style={{ width: 140, height: 14 }} />
              <span className="skeleton" style={{ width: 76, height: 14 }} />
              <span
                className="skeleton"
                style={{ width: 100, height: 12, gridColumn: "2 / -1" }}
              />
            </div>
          </div>
        </div>
      ) : defi.status === "error" ? (
        <div className="defi-empty error">
          <div className="defi-empty-ic">
            <Icon name="alert" size={18} />
          </div>
          <div>
            <div className="defi-empty-title">{t("wallet.defiError")}</div>
            <div className="defi-empty-sub">{defi.error}</div>
          </div>
        </div>
      ) : defi.positions.length > 0 ? (
        positions.length > 0 ? (
          <>
            {visiblePositions.length > 0 && (
              <div className="defi-list">
                {visiblePositions.map((position) => (
                  <DefiPositionCard key={position.id} position={position} />
                ))}
              </div>
            )}
            {hiddenSmallPositionCount > 0 && (
              <button
                type="button"
                className="defi-small-toggle"
                onClick={() => setShowSmallPositions((show) => !show)}
              >
                {showSmallPositions
                  ? t("wallet.hideSmallDefiPositions", {
                      count: hiddenSmallPositionCount,
                    })
                  : t("wallet.showSmallDefiPositions", {
                      count: hiddenSmallPositionCount,
                    })}
              </button>
            )}
          </>
        ) : (
          <div className="section-empty">{t("wallet.noDefiMatches")}</div>
        )
      ) : (
        <div className="defi-empty">
          <div className="defi-empty-ic">
            <Icon name="bridge" size={18} />
          </div>
          <div>
            <div className="defi-empty-title">{t("wallet.defiEmpty")}</div>
            <div className="defi-empty-sub">{t("wallet.defiEmptyHint")}</div>
          </div>
        </div>
      )}
    </section>
  );
}

function isSmallPricedDefiPosition(position: DefiState["positions"][number]): boolean {
  const hasKnownUsdValue =
    position.balanceUsd > 0 ||
    position.tokens.some((token) => token.balanceUsd != null);
  return hasKnownUsdValue && position.balanceUsd < 1;
}

function DefiPositionCard({
  position,
}: {
  position: DefiState["positions"][number];
}) {
  const symbols =
    position.symbols.length > 0
      ? position.symbols
      : position.tokens.map((token) => token.symbol);
  const detailTokens = position.tokens.filter(
    (token) => token.balance || token.balanceUsd != null,
  );
  const canOpen = !!position.appUrl;
  function openPositionDapp() {
    if (!position.appUrl) return;
    let url: URL;
    try {
      url = new URL(position.appUrl);
    } catch {
      return;
    }
    window.dispatchEvent(
      new CustomEvent("autodesktop:open-dapp", {
        detail: {
          id: `defi-${url.hostname}-${position.appName}`
            .toLowerCase()
            .replace(/[^a-z0-9_-]/g, "-"),
          url: url.toString(),
          name: position.appName,
          pinned: false,
        },
      }),
    );
  }
  const Tag = canOpen ? "button" : "div";
  return (
    <Tag
      className={`defi-card${canOpen ? " clickable" : ""}`}
      onClick={canOpen ? openPositionDapp : undefined}
      title={canOpen ? position.appUrl ?? undefined : undefined}
    >
      {/* Head grid: icon | title + value on row 1, label row spanning the
          full width on row 2 (so labels don't fight the value for space). */}
      <div className="defi-card-head">
        <div className="defi-app-icon">
          {position.appImageUrl ? (
            <img src={position.appImageUrl} alt="" />
          ) : (
            position.appName.slice(0, 2).toUpperCase()
          )}
        </div>
        <div className="defi-title">
          <span className="defi-app-name" title={position.appName}>
            {position.appName}
          </span>
          <span className="defi-network" title={position.networkName}>
            {position.networkName}
          </span>
        </div>
        <div className="defi-value tnum">{fmtUsd(position.balanceUsd)}</div>
        <div className="defi-label-row">
          <span className="defi-label" title={position.label}>
            {position.label}
          </span>
          {position.groupLabel && (
            <span className="defi-group-label" title={position.groupLabel}>
              {position.groupLabel}
            </span>
          )}
        </div>
      </div>
      {/* Body: full-width token table (aligned columns), or symbol chips when
          there is no per-token detail. Pinned to the card bottom so rows of
          cards keep their baselines aligned. */}
      {detailTokens.length > 0 ? (
        <div className="defi-token-breakdown">
          {detailTokens.slice(0, 4).map((token, index) => (
            <Fragment key={`${token.symbol}-${token.balance ?? index}`}>
              <span className="defi-token-symbol" title={token.symbol}>
                {token.symbol}
              </span>
              <span
                className="defi-token-amount"
                title={token.balance ?? undefined}
              >
                {token.balance ? formatDefiTokenAmount(token.balance) : ""}
              </span>
              <span className="defi-token-usd">
                {token.balanceUsd != null ? fmtUsd(token.balanceUsd) : ""}
              </span>
            </Fragment>
          ))}
        </div>
      ) : (
        symbols.length > 0 && (
          <div className="defi-symbols">
            {symbols.slice(0, 4).map((symbol) => (
              <span key={symbol}>{symbol}</span>
            ))}
          </div>
        )
      )}
    </Tag>
  );
}

function formatDefiTokenAmount(value: string): string {
  const n = Number.parseFloat(value);
  // From 1M up, compact (2.5M / 8.72B) instead of overflowing the card; the
  // exact value stays hoverable via the row's title.
  if (Number.isFinite(n) && Math.abs(n) >= 1_000_000) return fmtAmount(value);
  return trimAmount(value, 8);
}

// One sendable balance (native coin or held ERC-20) for the Send picker.
type SendAsset = {
  key: string;
  chainId: string;
  chainName: string;
  kind: "native" | "erc20";
  symbol: string;
  decimals: number;
  address?: string;
  color: string;
  logo?: string;
  wei: string;
};

type SwapStage =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "approving" }
  | { kind: "swapping" }
  | {
      kind: "submitted";
      hash: string;
      providerId: ProviderId;
      requestId?: string;
      // Frozen at submit time: the form stays editable afterwards, and the
      // explorer links must keep pointing at the chains this swap actually used.
      fromChainId: string;
      fromChainName: string;
      toChainId: string;
      toChainName: string;
    }
  | { kind: "error"; message: string };

type SwapPickerMode = "source" | "target";

type SwapPickerItem = {
  chainId: number;
  chainName: string;
  chainLogo?: string;
  chainSymbol?: string;
  key: string;
  token: ProviderToken | MergedToken;
  balance?: string;
  providers?: ProviderId[];
  sourceAssetKey?: string;
};

// A balance state — native (BalanceState) and ERC-20 (TokenBalance) are the same
// shape; the unified row carries whichever applies.
type BalState = BalanceState | TokenBalance | undefined;

// One line in the token list: a chain's native coin, or an ERC-20 held on it.
type DisplayRowBase = {
  key: string;
  /** 0x-hex chain id this row lives on (for the network filter). */
  chainId: string;
  chainName: string;
  chainSymbol: string;
  chainColor: string;
  symbol: string;
  name: string;
  decimals: number;
  /** Coin-glyph background color (chain brand for native, seeded for tokens). */
  color: string;
  logo?: string;
  state: BalState;
  price?: Price;
};

type DisplayRow = DisplayRowBase &
  (
    | { kind: "native"; address?: never; isCustom?: never }
    | { kind: "erc20"; address: string; isCustom: boolean }
  );

// Deterministic pleasant color from a string (token contract) — only used as the
// glyph background when a token has no logo.
function seedColor(seed: string): string {
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  return `hsl(${h % 360} 64% 55%)`;
}

function isHeld(st: BalState): boolean {
  return st?.status === "ok" && BigInt(st.wei) > 0n;
}

// Native (always) + ERC-20 (held>0 or user-added) rows for the shown chains.
function buildRows(
  shown: Chain[],
  custom: CustomStore,
  balances: Record<string, BalanceState>,
  tokenBalances: Record<string, TokenBalance>,
  prices: PriceState,
  tokenPrices: Record<string, Price>,
  options: { includeZeroDefaultTokens: boolean },
): DisplayRow[] {
  const rows: DisplayRow[] = [];
  for (const c of shown) {
    rows.push({
      key: `native:${c.id}`,
      chainId: c.id,
      chainName: c.name,
      chainSymbol: c.symbol,
      chainColor: c.color,
      kind: "native",
      symbol: c.symbol,
      name: `${c.name} ${c.symbol}`,
      decimals: c.decimals,
      color: c.color,
      logo: chainLogo(c.id),
      state: balances[c.id],
      price: priceForChainAsset(
        c.name,
        prices.status === "ok" ? prices.prices[c.symbol.toUpperCase()] : undefined,
      ),
    });
    for (const tk of tokensForChain(custom, c.id)) {
      const st = tokenBalances[tokenKey(c.id, tk.address)];
      const cust = isCustomToken(custom, c.id, tk.address);
      if (!options.includeZeroDefaultTokens && !cust && !isHeld(st)) continue;
      rows.push({
        key: `erc20:${c.id}:${tk.address}`,
        chainId: c.id,
        chainName: c.name,
        chainSymbol: c.symbol,
        chainColor: c.color,
        kind: "erc20",
        symbol: tk.symbol,
        name: tk.name,
        decimals: tk.decimals,
        address: tk.address,
        color: seedColor(tk.address),
        logo: tk.logo || undefined,
        state: st,
        price: priceForChainAsset(c.name, tokenPrices[tkPriceKey(c.id, tk.address)]),
        isCustom: cust,
      });
    }
  }
  return rows
    .map((row, index) => ({ row, index, usd: rowUsdValue(row) }))
    .sort((a, b) => {
      if (a.usd == null && b.usd == null) return a.index - b.index;
      if (a.usd == null) return 1;
      if (b.usd == null) return -1;
      return b.usd - a.usd || a.index - b.index;
    })
    .map(({ row }) => row);
}

function isZeroBalanceRow(row: DisplayRow): boolean {
  return row.state !== undefined && row.state.status === "ok" && BigInt(row.state.wei) === 0n;
}

function rowUsdValue(row: DisplayRow): number | null {
  if (!row.state || row.state.status !== "ok" || !row.price) return null;
  return weiToUsd(row.state.wei, row.decimals, row.price.usd);
}

function normalizedSearch(value: string): string {
  return value.trim().toLowerCase();
}

function includesQuery(query: string, values: Array<string | null | undefined>): boolean {
  if (!query) return true;
  return values.some((value) => value?.toLowerCase().includes(query));
}

function filterTokenRows(rows: DisplayRow[], query: string): DisplayRow[] {
  const q = normalizedSearch(query);
  if (!q) return rows;
  return rows.filter((row) =>
    includesQuery(q, [
      row.symbol,
      row.chainName,
      row.chainSymbol,
      row.address,
      row.kind,
    ]),
  );
}

function filterDefiPositions(
  positions: DefiState["positions"],
  query: string,
): DefiState["positions"] {
  const q = normalizedSearch(query);
  if (!q) return positions;
  return positions.filter((position) =>
    includesQuery(q, [
      position.appName,
      position.networkName,
      position.label,
      ...position.symbols,
      ...position.tokens.map((token) => token.symbol),
    ]),
  );
}

function computeWalletAssetsOverOneUsd(
  rows: DisplayRow[],
  pricesLoading: boolean,
): boolean | undefined {
  let sawLoading = pricesLoading;
  let sawPricedAsset = false;
  let total = 0;

  for (const row of rows) {
    if (!row.state || row.state.status === "loading") {
      sawLoading = true;
      continue;
    }
    if (row.state.status !== "ok" || !row.price) continue;

    sawPricedAsset = true;
    total += weiToUsd(row.state.wei, row.decimals, row.price.usd);
    if (total > 1) return true;
  }

  if (sawPricedAsset) return false;
  return sawLoading ? undefined : false;
}

function HeroAmount({ n, approximate = false }: { n: number; approximate?: boolean }) {
  const [whole, cents] = fmtUsd(n).replace("$", "").split(".");
  // Wrapped in one inline element: .hero-total is a flex row with a gap, so a
  // bare fragment would split "$144" and ".54" into separate flex items and
  // print a gap between them. Deliberately unanimated — the balance repolls on
  // a timer, so a per-digit re-entry just reads as the number flickering.
  return (
    <span className="hero-amt">
      {approximate ? "≈$" : "$"}
      {whole}
      <span className="cents">.{cents}</span>
    </span>
  );
}

function PortfolioSparkline({
  trend,
  onRemove,
}: {
  trend: PortfolioTrend;
  onRemove: (timestamp: number) => void;
}) {
  return (
    <div className="hero-chart">
      {/* The curve carries no information the labels don't; the delete buttons
          on those labels do, so the container itself can't be aria-hidden. */}
      <svg viewBox="0 0 320 118" preserveAspectRatio="none" aria-hidden="true">
        <defs>
          <linearGradient id="portfolioLineFade" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0" />
            <stop offset="15%" stopColor="currentColor" stopOpacity="0.72" />
            <stop offset="82%" stopColor="currentColor" stopOpacity="0.88" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
          <linearGradient id="portfolioAreaFade" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="currentColor" stopOpacity="0.2" />
            <stop offset="100%" stopColor="currentColor" stopOpacity="0" />
          </linearGradient>
        </defs>
        <path className="hero-chart-area" d={trend.areaPath} />
        {/* The box is far wider than the viewBox is tall and the aspect ratio is
            not preserved, so a scaled stroke comes out heavy on the verticals
            and thin on the horizontals. Non-scaling keeps one hairline weight
            in screen pixels all the way round. */}
        <path
          className="hero-chart-line"
          d={trend.path}
          vectorEffect="non-scaling-stroke"
        />
      </svg>
      {trend.high && (
        <TrendMark mark={trend.high} kind="high" onRemove={onRemove} />
      )}
      {trend.low && <TrendMark mark={trend.low} kind="low" onRemove={onRemove} />}
    </div>
  );
}

function TrendMark({
  mark,
  kind,
  onRemove,
}: {
  mark: TrendExtreme;
  kind: "high" | "low";
  onRemove: (timestamp: number) => void;
}) {
  const { t, lang } = useT();
  // Both sit on the true point. Near an edge the label flips from centred to
  // left/right aligned rather than being nudged inward — a peak at either end
  // would otherwise print its label floating away from its own dot.
  const x = mark.xPct * 100;
  const y = mark.yPct * 100;
  const align = x < 12 ? "start" : x > 88 ? "end" : "center";
  return (
    <>
      <span
        className={`hero-chart-dot is-${kind}`}
        style={{ left: `${x}%`, top: `${y}%` }}
      />
      <span
        className={`hero-chart-tag is-${kind} at-${align}${mark.deletable ? " is-deletable" : ""}`}
        style={{ left: `${x}%`, top: `${y}%` }}
      >
        <b className="tnum">{fmtUsd(mark.totalUsd, { dp: mark.totalUsd >= 1000 ? 0 : 2 })}</b>
        <i>{formatTrendDate(mark.timestamp, lang)}</i>
        {/* A reading taken while a source was still loading sits in the history
            as a peak or a trough that never happened — which is exactly where
            this label is. Hover it to throw that reading away. */}
        {mark.deletable && (
          <button
            type="button"
            className="hero-chart-del"
            title={t("wallet.trendPointRemove")}
            aria-label={t("wallet.trendPointRemove")}
            onClick={() => onRemove(mark.timestamp)}
          >
            {/* At 9px the 1.7 grid stroke scales to 0.6px and goes grey — a
                thicker one keeps the cross a hairline instead of a smudge. */}
            <Icon name="close" size={9} sw={2.6} />
          </button>
        )}
      </span>
    </>
  );
}

function formatTrendDate(timestamp: number, lang: Lang): string {
  return new Date(timestamp * 1000).toLocaleDateString(localeTag(lang), {
    month: "short",
    day: "numeric",
  });
}

function HeroAction({
  icon,
  label,
  onClick,
  hover,
}: {
  icon: IconName;
  label: string;
  onClick: () => void;
  hover?: { className: string; onMouseEnter: () => void };
}) {
  return (
    <button
      {...hover}
      className={`hero-action${hover ? ` ${hover.className}` : ""}`}
      onClick={onClick}
    >
      <Icon name={icon} size={16} />
      <span>{label}</span>
    </button>
  );
}

function Coin({
  symbol,
  color,
  size = 40,
  logo,
}: {
  symbol: string;
  color: string;
  size?: number;
  logo?: string;
}) {
  const [broken, setBroken] = useState(false);
  const letters = symbol.slice(0, symbol.length > 3 ? 3 : symbol.length);
  return (
    <span className="coin" style={{ width: size, height: size }}>
      {logo && !broken ? (
        <img
          className="coin-img"
          src={logo}
          width={size}
          height={size}
          alt=""
          onError={() => setBroken(true)}
        />
      ) : (
        <span
          className="coin-glyph"
          style={{
            width: size,
            height: size,
            background: color,
            fontSize: letters.length > 2 ? 11 : 13,
          }}
        >
          {letters}
        </span>
      )}
    </span>
  );
}

// Token-first row (#5): the token symbol is the headline, the chain it lives on is
// the secondary tag. Works for both the native coin and held ERC-20s.
export function HoldingRow({
  row,
  t,
  canSign,
  onOpen,
  onSend,
  onSwap,
  onRetry,
}: {
  row: DisplayRow;
  t: TFn;
  canSign: boolean;
  onOpen: () => void;
  onSend: (assetKey: string) => void;
  onSwap: (assetKey: string) => void;
  onRetry: () => void;
}) {
  const usd =
    row.state?.status === "ok" && row.price
      ? weiToUsd(row.state.wei, row.decimals, row.price.usd)
      : null;
  const showPriceChange = !!row.price && !row.price.synthetic;
  const up = (row.price?.change24h ?? 0) >= 0;
  const sendAssetKey =
    row.kind === "native"
      ? `n:${row.chainId}`
      : `e:${row.chainId}:${row.address}`;
  const canSend =
    canSign &&
    row.state?.status === "ok" &&
    BigInt(row.state.wei) > 0n;
  return (
    <div
      className="token-card"
      style={{ "--tk": row.color } as React.CSSProperties}
      role="button"
      tabIndex={0}
      aria-label={t("wallet.openTokenDetails", { symbol: row.symbol })}
      onClick={onOpen}
      onKeyDown={(event) => {
        if (event.target !== event.currentTarget) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onOpen();
        }
      }}
    >
      <div className="token-id">
        <Coin symbol={row.symbol} color={row.color} logo={row.logo} size={36} />
        <div className="token-id-meta">
          <span className="token-name">
            {row.symbol}
            {row.isCustom && (
              <span className="badge neutral">{t("wallet.custom")}</span>
            )}
          </span>
          <span className="token-sub">
            <ChainIcon
              chain={{
                id: row.chainId,
                name: row.chainName,
                symbol: row.chainSymbol,
                color: row.chainColor,
              }}
              size={11}
            />
            <span className="token-chain" title={row.chainName}>
              {row.chainName}
            </span>
          </span>
        </div>
      </div>
      {/* Two zones, both edges anchored: identity left, numbers right (money
          aligns right). Hierarchy inside the number zone: balance is the
          headline, then one quiet line — value · @price · 24h (the change
          belongs to the price, so it lives there, not in a lonely corner). */}
      {!row.state || row.state.status === "loading" ? (
        <div className="token-nums">
          <span className="skeleton" style={{ width: 96, height: 15 }} />
          <span className="skeleton" style={{ width: 64, height: 11 }} />
        </div>
      ) : row.state.status === "error" ? (
        <div className="token-nums">
          <span className="token-err">{t("wallet.balanceFailed")}</span>
          <span className="token-err-reason" title={row.state.message}>
            {row.state.message}
          </span>
          <button
            type="button"
            className="token-err-retry"
            onClick={(event) => {
              event.stopPropagation();
              onRetry();
            }}
          >
            {t("wallet.retry")}
          </button>
        </div>
      ) : (
        <div className="token-nums">
          <div
            className="token-balance disp tnum"
            title={`${formatUnits(row.state.wei, row.decimals, row.decimals)} ${row.symbol}`}
          >
            {fmtUnitsDisplay(row.state.wei, row.decimals)}
            <span className="token-balance-sym">{row.symbol}</span>
          </div>
          <div className="token-card-foot">
            {usd != null && (
              <span className="token-value tnum">{fmtUsd(usd)}</span>
            )}
            {row.price && (
              <span className="token-price tnum">
                @ {fmtUsd(row.price.usd, { dp: row.price.usd < 1 ? 4 : 2 })}
              </span>
            )}
            {row.price && showPriceChange && (
              <span className={`token-chg ${up ? "up" : "down"}`}>
                {fmtPct(row.price.change24h)}
              </span>
            )}
          </div>
        </div>
      )}
      {/* A failed row has nothing to send, and the hover actions would sit on
          top of its Retry button. */}
      {row.state?.status !== "error" && (
        <div className="token-actions">
          <button
            className="token-action send"
            disabled={!canSend}
            onClick={(event) => {
              event.stopPropagation();
              onSend(sendAssetKey);
            }}
          >
            <Icon name="send" size={12} /> {t("wallet.send")}
          </button>
          <button
            className="token-action"
            disabled={!canSend}
            onClick={(event) => {
              event.stopPropagation();
              onSwap(sendAssetKey);
            }}
          >
            <Icon name="swap" size={12} /> {t("wallet.swap")}
          </button>
        </div>
      )}
    </div>
  );
}

function TokenDetailModal({
  row,
  canSign,
  onClose,
  onReceive,
  onSend,
  onSwap,
}: {
  row: DisplayRow;
  canSign: boolean;
  onClose: () => void;
  onReceive: () => void;
  onSend: (assetKey: string) => void;
  onSwap: (assetKey: string) => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  const chain = findChain(row.chainId);
  const assetKey =
    row.kind === "native" ? `n:${row.chainId}` : `e:${row.chainId}:${row.address}`;
  const hasBalance =
    row.state?.status === "ok" && BigInt(row.state.wei) > 0n;
  const canMove = canSign && hasBalance;
  const usd =
    row.state?.status === "ok" && row.price
      ? weiToUsd(row.state.wei, row.decimals, row.price.usd)
      : null;
  const explorerUrl =
    row.kind === "erc20"
      ? explorerTokenUrl(chain, row.chainId, row.chainName, row.address)
      : null;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") close();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [close]);

  return (
    <div className={`scrim token-detail-scrim t-scrim ${cls}`} onClick={close}>
      <div
        className={`modal token-detail-modal t-modal ${cls}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="token-detail-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-head token-detail-head">
          <div className="token-detail-heading">
            <Coin symbol={row.symbol} color={row.color} logo={row.logo} size={48} />
            <div>
              <div className="token-detail-symbol" id="token-detail-title">
                {row.symbol}
                {row.isCustom && (
                  <span className="badge neutral">{t("wallet.custom")}</span>
                )}
              </div>
              <div className="token-detail-name">{row.name}</div>
            </div>
          </div>
          <button
            className="icon-btn bare"
            onClick={close}
            aria-label={t("common.close")}
          >
            <Icon name="close" size={18} />
          </button>
        </div>

        <div className="modal-body token-detail-body">
          <div className="token-detail-balance">
            <span>{t("wallet.balance")}</span>
            {row.state?.status === "ok" ? (
              <strong className="disp tnum">
                {fmtUnitsDisplay(row.state.wei, row.decimals)}
                <small>{row.symbol}</small>
              </strong>
            ) : row.state?.status === "error" ? (
              <strong className="token-detail-error">{t("wallet.balanceUnavailable")}</strong>
            ) : (
              <span className="skeleton" style={{ width: 150, height: 28 }} />
            )}
            {usd != null && <em className="tnum">{fmtUsd(usd)}</em>}
          </div>

          <div className="token-detail-actions">
            <button disabled={!canMove} onClick={() => onSend(assetKey)}>
              <span><Icon name="send" size={17} /></span>
              {t("wallet.send")}
            </button>
            <button disabled={!canMove} onClick={() => onSwap(assetKey)}>
              <span><Icon name="swap" size={17} /></span>
              {t("wallet.swap")}
            </button>
            <button onClick={onReceive}>
              <span><Icon name="receive" size={17} /></span>
              {t("wallet.receive")}
            </button>
            {explorerUrl && (
              <button onClick={() => void openExternalUrl(explorerUrl)}>
                <span><Icon name="external" size={17} /></span>
                {t("wallet.explorer")}
              </button>
            )}
          </div>

          <div className="token-detail-stats">
            <TokenDetailStat
              label={t("wallet.price")}
              value={row.price ? fmtUsd(row.price.usd, { dp: row.price.usd < 1 ? 4 : 2 }) : "—"}
            />
            <TokenDetailStat
              label={t("wallet.change24h")}
              value={
                row.price && !row.price.synthetic ? fmtPct(row.price.change24h) : "—"
              }
              tone={
                row.price && !row.price.synthetic
                  ? row.price.change24h >= 0
                    ? "up"
                    : "down"
                  : undefined
              }
            />
            <TokenDetailStat label={t("wallet.decimals")} value={String(row.decimals)} />
          </div>

          <div className="token-detail-info">
            <div className="token-detail-info-row">
              <span>{t("wallet.network")}</span>
              <strong>
                <ChainIcon
                  chain={{
                    id: row.chainId,
                    name: row.chainName,
                    symbol: row.chainSymbol,
                    color: row.chainColor,
                  }}
                  size={15}
                />
                {row.chainName}
              </strong>
            </div>
            <div className="token-detail-info-row">
              <span>{t("wallet.tokenType")}</span>
              <strong>{row.kind === "erc20" ? "ERC-20" : t("wallet.nativeToken")}</strong>
            </div>
            <div className="token-detail-address">
              <span>{t("wallet.tokenAddress")}</span>
              {row.address ? (
                <div className="token-detail-address-box">
                  <code>{row.address}</code>
                  <CopyButton
                    className="icon-btn"
                    title={t("wallet.copy")}
                    size={15}
                    value={row.address}
                    onCopied={() => toast(t("common.copied"))}
                  />
                </div>
              ) : (
                <strong className="token-detail-native-note">
                  {t("wallet.nativeNoContract")}
                </strong>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

function TokenDetailStat({
  label,
  value,
  tone,
}: {
  label: string;
  value: string;
  tone?: "up" | "down";
}) {
  return (
    <div>
      <span>{label}</span>
      <strong className={`tnum${tone ? ` ${tone}` : ""}`}>{value}</strong>
    </div>
  );
}

function ActivityList({
  records,
  chains,
  t,
  lang,
  onReplace,
}: {
  records: ActivityRecord[];
  chains: Chain[];
  t: TFn;
  lang: Lang;
  onReplace: (record: ActivityRecord, action: "speedup" | "cancel") => void;
}) {
  if (records.length === 0) {
    return (
      <div className="empty">
        <div className="empty-ic">
          <Icon name="activity" size={28} />
        </div>
        {t("wallet.activityEmpty")}
      </div>
    );
  }
  return (
    <div className="activity-list">
      {records.map((record) => {
        const chain = chains.find(
          (c) => c.id.toLowerCase() === record.chainId.toLowerCase(),
        );
        const href = txExplorerUrl(chain, record);
        const isTokenSend = record.kind === "token_send";
        const balanceChanges = record.balanceChanges?.filter(
          (c) => c.formattedDelta && c.symbol,
        ) ?? [];
        const amount = record.amount ?? record.value;
        const amountWei = safeHexToBigInt(amount);
        const decimals =
          record.assetDecimals ??
          (isTokenSend ? undefined : (chain?.decimals ?? 18));
        const symbol =
          record.assetSymbol ??
          (isTokenSend ? t("wallet.activityToken") : record.symbol);
        const swap = record.swap ?? null;
        const label = swap
          ? t("wallet.activitySwapVia", { provider: swap.provider })
          : record.kind === "speedup"
            ? t("wallet.speedUpTx")
            : record.kind === "cancel"
              ? t("wallet.revokeTx")
              : isTokenSend
                ? t("wallet.activityTokenSend")
                : record.kind === "contract"
                  ? t("wallet.activityContract")
                  : t("wallet.activitySend");
        const counterparty = record.counterparty || record.to || record.hash;
        const statusLabel =
          record.status === "failed"
            ? t("wallet.activityFailed")
            : record.status === "confirmed"
              ? t("wallet.activityConfirmed")
              : record.status === "replaced"
                ? t("wallet.activityReplaced")
                : t("wallet.activitySubmitted");
        const statusClass =
          record.status === "failed"
            ? " failed"
            : record.status === "confirmed"
              ? " confirmed"
              : record.status === "replaced"
                ? " replaced"
                : " submitted";
        const canReplace =
          record.status !== "confirmed" &&
          record.status !== "failed" &&
          record.status !== "replaced" &&
          !!record.nonce &&
          !!record.gas;
        return (
          <div
            key={record.id}
            className={`activity-row${statusClass}${href ? "" : " disabled"}`}
            role="button"
            tabIndex={href ? 0 : -1}
            onClick={() => href && void openExternalUrl(href)}
            onKeyDown={(event) => {
              if (href && (event.key === "Enter" || event.key === " ")) {
                event.preventDefault();
                void openExternalUrl(href);
              }
            }}
            title={href ? t("wallet.openExplorer") : t("wallet.noExplorer")}
          >
            <span className={`activity-ic ${record.kind}`}>
              <Icon
                name={
                  record.kind === "swap"
                    ? "swap"
                    : record.kind === "contract" || record.kind === "speedup"
                      ? "doc"
                      : "send"
                }
                size={17}
              />
            </span>
            <span className="activity-main">
              <span className="activity-title">
                {label}
                <span className="activity-chain">
                  {swap
                    ? `${swap.fromChainName} → ${swap.toChainName}`
                    : (chain?.name ?? record.chainName)}
                </span>
              </span>
              <span className="activity-sub">
                {swap
                  ? `${swap.fromSymbol} → ${swap.toSymbol}`
                  : `${shortAddress(counterparty, 10, 8)} · ${record.origin}`}
              </span>
              <span className="activity-hash">
                {shortAddress(record.hash, 10, 8)}
                <span> · {statusLabel}</span>
              </span>
            </span>
            <span className="activity-right">
              {swap ? (
                <span className="activity-changes">
                  <span
                    className="activity-change split out"
                    title={`-${formatUnits(swap.fromAmount, swap.fromDecimals, swap.fromDecimals)} ${swap.fromSymbol}`}
                  >
                    <span className="activity-change-num">
                      -{fmtUnitsDisplay(swap.fromAmount, swap.fromDecimals)}
                    </span>
                    <span className="activity-change-sym">{swap.fromSymbol}</span>
                  </span>
                  <span
                    className="activity-change split in"
                    title={`+${formatUnits(swap.toAmount, swap.toDecimals, swap.toDecimals)} ${swap.toSymbol}`}
                  >
                    <span className="activity-change-num">
                      +{fmtUnitsDisplay(swap.toAmount, swap.toDecimals)}
                    </span>
                    <span className="activity-change-sym">{swap.toSymbol}</span>
                  </span>
                </span>
              ) : balanceChanges.length > 0 ? (
                <span className="activity-changes">
                  {balanceChanges.slice(0, 3).map((change, index) => (
                    <span
                      key={`${change.symbol}:${change.formattedDelta}:${index}`}
                      className={`activity-change split ${change.direction === "in" ? "in" : "out"}`}
                      title={`${change.formattedDelta} ${change.symbol}`}
                    >
                      <span className="activity-change-num">
                        {change.formattedDelta}
                      </span>
                      <span className="activity-change-sym">{change.symbol}</span>
                    </span>
                  ))}
                </span>
              ) : (
                <span className="activity-value">
                  {amountWei > 0n && decimals != null
                    ? `${fmtUnitsDisplay(amount, decimals)} ${symbol}`
                    : t("wallet.activityNoValue")}
                </span>
              )}
              <span className="activity-time">
                {formatActivityTime(record.timestamp, lang)}
              </span>
              {canReplace && (
                <span className="activity-actions">
                  <button
                    type="button"
                    className="mini-action"
                    onClick={(event) => {
                      event.stopPropagation();
                      onReplace(record, "speedup");
                    }}
                  >
                    {t("wallet.speedUp")}
                  </button>
                  <button
                    type="button"
                    className="mini-action danger"
                    onClick={(event) => {
                      event.stopPropagation();
                      onReplace(record, "cancel");
                    }}
                  >
                    {t("wallet.revokeTx")}
                  </button>
                </span>
              )}
            </span>
            {href && <Icon name="external" size={15} />}
          </div>
        );
      })}
    </div>
  );
}

function safeHexToBigInt(value: string | null | undefined): bigint {
  try {
    return BigInt(value || "0x0");
  } catch {
    return 0n;
  }
}

function formatActivityTime(timestamp: number, lang: Lang): string {
  if (!timestamp) return "";
  return new Date(timestamp * 1000).toLocaleString(localeTag(lang), {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function feeHexToGwei(value: string | null | undefined): string {
  if (!value) return "";
  try {
    const formatted = formatUnits(value, 9);
    return formatted.replace(/\.?0+$/, "");
  } catch {
    return "";
  }
}

function ReplaceTxModal({
  record,
  action,
  t,
  onClose,
  onSubmit,
}: {
  record: ActivityRecord;
  action: "speedup" | "cancel";
  t: TFn;
  onClose: () => void;
  onSubmit: (maxFeePerGas: string, maxPriorityFeePerGas: string) => Promise<void>;
}) {
  const [maxFee, setMaxFee] = useState(() => feeHexToGwei(record.maxFeePerGas));
  const [priorityFee, setPriorityFee] = useState(() =>
    feeHexToGwei(record.maxPriorityFeePerGas),
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const { cls, close } = useModalExit(onClose);

  async function submit() {
    setError(null);
    let maxHex: string;
    let priorityHex: string;
    try {
      maxHex = toHexQuantity(parseUnits(cleanDecimal(maxFee), 9));
      priorityHex = toHexQuantity(parseUnits(cleanDecimal(priorityFee), 9));
    } catch {
      setError(t("wallet.invalidGas"));
      return;
    }
    if (safeHexToBigInt(priorityHex) > safeHexToBigInt(maxHex)) {
      setError(t("wallet.priorityTooHigh"));
      return;
    }
    if (safeHexToBigInt(maxHex) <= 0n) {
      setError(t("wallet.invalidGas"));
      return;
    }
    setBusy(true);
    try {
      await onSubmit(maxHex, priorityHex);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div
        className={`modal replace-modal t-modal ${cls}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <h2>
            {action === "speedup" ? t("wallet.speedUpTx") : t("wallet.revokeTx")}
          </h2>
          <button className="icon-btn" onClick={close} aria-label="Close">
            <Icon name="x" size={20} />
          </button>
        </div>
        <div className="replace-summary">
          <span>{t("wallet.originalTx")}</span>
          <strong>{shortAddress(record.hash, 10, 8)}</strong>
          <span>{record.chainName}</span>
        </div>
        <label className="field">
          <span>{t("wallet.maxFeePerGas")}</span>
          <div className="fee-input-row">
            <input
              className="input"
              value={maxFee}
              onChange={(e) => setMaxFee(e.target.value)}
              placeholder="0"
            />
            <span>Gwei</span>
          </div>
        </label>
        <label className="field">
          <span>{t("wallet.priorityFee")}</span>
          <div className="fee-input-row">
            <input
              className="input"
              value={priorityFee}
              onChange={(e) => setPriorityFee(e.target.value)}
              placeholder="0"
            />
            <span>Gwei</span>
          </div>
        </label>
        <div className="hint">
          <Icon name="info" size={14} />
          {action === "speedup" ? t("wallet.speedUpHint") : t("wallet.revokeHint")}
        </div>
        {error && <div className="error-line">{error}</div>}
        <div className="modal-actions">
          <button className="btn ghost" onClick={close}>
            {t("wallet.cancel")}
          </button>
          <button className="btn primary" onClick={submit} disabled={busy}>
            {busy ? t("wallet.submitting") : t("common.confirm")}
          </button>
        </div>
      </div>
    </div>
  );
}

function KindBadge({
  kind,
  t,
}: {
  kind: WalletInfo["kind"] | "watch" | "safe";
  t: TFn;
}) {
  if (kind === "ledger")
    return (
      <span className="badge ledger">
        <Icon name="ledger" size={11} /> Ledger
      </span>
    );
  if (kind === "privkey")
    return (
      <span className="badge neutral">
        <Icon name="key" size={11} /> {t("lock.importTab.privkey")}
      </span>
    );
  if (kind === "watch")
    return (
      <span className="badge neutral">
        <Icon name="eye" size={11} /> {t("wallet.watch")}
      </span>
    );
  if (kind === "safe")
    return (
      <span className="badge neutral">
        <Icon name="shield" size={11} /> Safe
      </span>
    );
  return null;
}

function AccountSwitcher() {
  const { t } = useT();
  const vault = useVault();
  const safes = useSafes();
  const accounts = useAccounts();
  const active = useActiveAccount();
  const [open, setOpen] = useState(false);
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<string | null>(null);
  const [renamingWatch, setRenamingWatch] = useState<string | null>(null);
  const [renamingSafe, setRenamingSafe] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [pinned, setPinned] = useState<string[]>(() => loadPinnedAccounts());
  const renamingAny =
    renaming !== null || renamingWatch !== null || renamingSafe !== null;
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (accountMenuClosesOnKey(e.key, { renaming: renamingAny, adding }))
        setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, renamingAny, adding]);

  const watchAccounts = accounts.filter((a) => a.kind === "watch");
  const pinnedSet = useMemo(() => new Set(pinned), [pinned]);
  const q = query.trim().toLowerCase();
  const visibleWallets = useMemo(() => {
    return vault.wallets
      .map((w) => {
        const walletHaystack = [w.label, w.kind, w.id].join(" ").toLowerCase();
        const matchedAccounts = w.accounts
          .map((addr, i) => ({ addr, index: i }))
          .filter(({ addr, index }) => {
            if (!q) return true;
            const accountLabel =
              w.accounts.length > 1
                ? `${t("wallet.account")} ${index + 1}`
                : "";
            return [
              walletHaystack,
              addr,
              shortAddress(addr, 12, 8),
              accountLabel,
            ]
              .join(" ")
              .toLowerCase()
              .includes(q);
          })
          .sort(
            (a, b) =>
              Number(pinnedSet.has(b.addr.toLowerCase())) -
              Number(pinnedSet.has(a.addr.toLowerCase())),
          );
        return {
          wallet: w,
          accounts: matchedAccounts,
          pinned: matchedAccounts.some((a) =>
            pinnedSet.has(a.addr.toLowerCase()),
          ),
        };
      })
      .filter((g) => g.accounts.length > 0)
      .sort((a, b) => Number(b.pinned) - Number(a.pinned));
  }, [pinnedSet, q, t, vault.wallets]);

  const visibleWatchAccounts = useMemo(() => {
    return watchAccounts
      .filter((a) => {
        if (!q) return true;
        return [
          a.label,
          a.address,
          shortAddress(a.address, 10, 6),
          t("wallet.watchGroup"),
        ]
          .join(" ")
          .toLowerCase()
          .includes(q);
      })
      .sort(
        (a, b) =>
          Number(pinnedSet.has(b.address.toLowerCase())) -
          Number(pinnedSet.has(a.address.toLowerCase())),
      );
  }, [pinnedSet, q, t, watchAccounts]);

  const visibleSafes = useMemo(() => {
    return safes
      .filter((safe) => {
        if (!q) return true;
        return [
          safe.label,
          safe.address,
          safe.ownerAddress,
          shortAddress(safe.address, 10, 6),
          "Safe",
        ]
          .join(" ")
          .toLowerCase()
          .includes(q);
      })
      .sort(
        (a, b) =>
          Number(pinnedSet.has(b.address.toLowerCase())) -
          Number(pinnedSet.has(a.address.toLowerCase())),
      );
  }, [pinnedSet, q, safes]);

  const visibleCount =
    visibleWallets.reduce((sum, g) => sum + g.accounts.length, 0) +
    visibleSafes.length +
    visibleWatchAccounts.length;

  function togglePinned(address: string) {
    const key = address.toLowerCase();
    setPinned((current) => {
      const next = current.includes(key)
        ? current.filter((addr) => addr !== key)
        : [key, ...current];
      savePinnedAccounts(next);
      return next;
    });
  }

  function close() {
    setOpen(false);
    setRenaming(null);
    setRenamingWatch(null);
    setRenamingSafe(null);
    setQuery("");
  }

  return (
    <div className="acct-switch">
      <button
        className="acct-pill"
        onClick={() => setOpen((o) => !o)}
        title={t("wallet.switchAccount")}
      >
        <Avatar address={active.address} size={34} />
        <div className="acct-pill-meta">
          <div className="nm">
            {active.label}
            {active.kind === "ledger" && (
              <span className="badge ledger">
                <Icon name="ledger" size={11} /> Ledger
              </span>
            )}
            {active.kind === "watch" && (
              <span className="badge neutral">
                <Icon name="eye" size={11} /> {t("wallet.watch")}
              </span>
            )}
            {active.kind === "safe" && <KindBadge kind="safe" t={t} />}
          </div>
          <div className="ad">{shortAddress(active.address, 8, 6)}</div>
        </div>
        <Icon name="chevronD" size={16} />
      </button>

      {open && (
        <>
          <div
            style={{ position: "fixed", inset: 0, zIndex: 30 }}
            onClick={close}
          />
          <div className="acct-menu scroll">
            <div className="acct-menu-head">
              <span>{t("wallet.wallets")}</span>
              <div className="acct-menu-head-actions">
                <span>{vault.wallets.length + safes.length}</span>
                <button
                  type="button"
                  className="acct-add-wallet-top"
                  onClick={() => setAdding(true)}
                >
                  <Icon name="plus" size={13} /> {t("wallet.addWallet")}
                </button>
              </div>
            </div>
            <label className="acct-search">
              <Icon name="search" size={15} />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder={t("wallet.searchAccounts")}
                autoComplete="off"
              />
            </label>

            {visibleWallets.map(({ wallet: w, accounts: matchedAccounts }) => (
              <WalletGroup
                key={w.id}
                wallet={w}
                accounts={matchedAccounts}
                active={active}
                t={t}
                renaming={renaming === w.id}
                pinnedSet={pinnedSet}
                onRename={() => setRenaming(w.id)}
                onRenameDone={() => setRenaming(null)}
                onTogglePinned={togglePinned}
                onPick={(addr) => {
                  setActive(addr);
                  close();
                }}
              />
            ))}

            {visibleWatchAccounts.length > 0 && (
              <div className="acct-group">
                <div className="acct-group-head">
                  <span>{t("wallet.watchGroup")}</span>
                </div>
                {visibleWatchAccounts.map((a) => {
                  const isPinned = pinnedSet.has(a.address.toLowerCase());
                  return (
                    <WatchAccountRow
                      key={a.address}
                      account={a}
                      activeAddress={active.address}
                      isPinned={isPinned}
                      renaming={renamingWatch === a.address}
                      t={t}
                      onPick={() => {
                        setActive(a.address);
                        close();
                      }}
                      onRename={() => setRenamingWatch(a.address)}
                      onRenameDone={() => setRenamingWatch(null)}
                      onTogglePinned={() => togglePinned(a.address)}
                      onRemove={async () => {
                        if (
                          await askConfirm({
                            title: t("wallet.deleteWatchConfirm"),
                            confirmLabel: t("wallet.delete"),
                            danger: true,
                          })
                        ) {
                          removeWatchAccount(a.address);
                          toast(t("wallet.removed"));
                        }
                      }}
                    />
                  );
                })}
              </div>
            )}

            {visibleSafes.length > 0 && (
              <div className="acct-group">
                <div className="acct-group-head">
                  <span>{t("safe.group")}</span>
                </div>
                {visibleSafes.map((safe) => {
                  const isPinned = pinnedSet.has(safe.address.toLowerCase());
                  return (
                    <SafeAccountRow
                      key={safe.address}
                      safe={safe}
                      activeAddress={active.address}
                      isPinned={isPinned}
                      renaming={renamingSafe === safe.address}
                      t={t}
                      onPick={() => {
                        setActive(safe.address);
                        close();
                      }}
                      onRename={() => setRenamingSafe(safe.address)}
                      onRenameDone={() => setRenamingSafe(null)}
                      onTogglePinned={() => togglePinned(safe.address)}
                      onRemove={async () => {
                        if (
                          await askConfirm({
                            title: t("safe.removeConfirm"),
                            confirmLabel: t("wallet.delete"),
                            danger: true,
                          })
                        ) {
                          removeSafeAccount(safe.address);
                          toast(t("wallet.removed"));
                        }
                      }}
                    />
                  );
                })}
              </div>
            )}

            {visibleCount === 0 && (
              <div className="acct-empty">{t("wallet.noAccountMatches")}</div>
            )}

            <button className="acct-add-wallet" onClick={() => setAdding(true)}>
              <Icon name="plus" size={16} /> {t("wallet.addWallet")}
            </button>
          </div>
        </>
      )}

      {adding && (
        <AddWalletModal
          hasPassword={vault.hasPassword}
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            close();
          }}
        />
      )}
    </div>
  );
}

function WatchAccountRow({
  account,
  activeAddress,
  isPinned,
  renaming,
  t,
  onPick,
  onRename,
  onRenameDone,
  onTogglePinned,
  onRemove,
}: {
  account: Account;
  activeAddress: string;
  isPinned: boolean;
  renaming: boolean;
  t: TFn;
  onPick: () => void;
  onRename: () => void;
  onRenameDone: () => void;
  onTogglePinned: () => void;
  onRemove: () => void;
}) {
  const [name, setName] = useState(account.label);

  async function saveName() {
    const next = name.trim();
    if (next && next !== account.label) {
      renameWatchAccount(account.address, next);
      toast(t("wallet.renamed"));
    }
    onRenameDone();
  }

  return (
    <div
      className={`acct-row${account.address === activeAddress ? " on" : ""}`}
    >
      {renaming ? (
        <div className="acct-row-main">
          <Avatar address={account.address} size={30} />
          <input
            className="input acct-watch-rename"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void saveName();
              if (e.key === "Escape") onRenameDone();
            }}
            onBlur={() => void saveName()}
          />
        </div>
      ) : (
        <button className="acct-row-main" onClick={onPick}>
          <Avatar address={account.address} size={30} />
          <div className="meta">
            <div className="l">{account.label}</div>
            <div className="a">{shortAddress(account.address, 10, 6)}</div>
          </div>
          {account.address === activeAddress && (
            <span className="check">
              <Icon name="check" size={16} />
            </span>
          )}
        </button>
      )}
      <button
        className={`icon-btn bare acct-pin${isPinned ? " on" : ""}`}
        title={t(isPinned ? "wallet.unpinAccount" : "wallet.pinAccount")}
        onClick={onTogglePinned}
      >
        <Icon name="star" size={15} />
      </button>
      <CopyButton
        className="icon-btn bare acct-copy"
        title={t("wallet.copy")}
        size={15}
        value={account.address}
        onCopied={() => toast(t("common.copied"))}
      />
      <button
        className="icon-btn bare acct-row-edit"
        title={t("wallet.rename")}
        onClick={onRename}
      >
        <Icon name="edit" size={15} />
      </button>
      <button
        className="icon-btn bare acct-row-act"
        title={t("wallet.removeWatch")}
        onClick={onRemove}
      >
        <Icon name="trash" size={15} />
      </button>
    </div>
  );
}

function SafeAccountRow({
  safe,
  activeAddress,
  isPinned,
  renaming,
  t,
  onPick,
  onRename,
  onRenameDone,
  onTogglePinned,
  onRemove,
}: {
  safe: ImportedSafe;
  activeAddress: string;
  isPinned: boolean;
  renaming: boolean;
  t: TFn;
  onPick: () => void;
  onRename: () => void;
  onRenameDone: () => void;
  onTogglePinned: () => void;
  onRemove: () => void;
}) {
  const [name, setName] = useState(safe.label);

  function saveName() {
    const next = name.trim();
    if (next && next !== safe.label) {
      renameSafeAccount(safe.address, next);
      toast(t("wallet.renamed"));
    }
    onRenameDone();
  }

  return (
    <div className={`acct-row${safe.address === activeAddress ? " on" : ""}`}>
      {renaming ? (
        <div className="acct-row-main">
          <Avatar address={safe.address} size={30} />
          <input
            className="input acct-watch-rename"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") saveName();
              if (e.key === "Escape") onRenameDone();
            }}
            onBlur={saveName}
          />
        </div>
      ) : (
        <button className="acct-row-main" onClick={onPick}>
          <Avatar address={safe.address} size={30} />
          <div className="meta">
            <div className="l">
              {safe.label} <KindBadge kind="safe" t={t} />
            </div>
            <div className="a">
              {shortAddress(safe.address, 10, 6)} · {safe.threshold}/
              {safe.owners.length}
            </div>
          </div>
          {safe.address === activeAddress && (
            <span className="check">
              <Icon name="check" size={16} />
            </span>
          )}
        </button>
      )}
      <button
        className={`icon-btn bare acct-pin${isPinned ? " on" : ""}`}
        title={t(isPinned ? "wallet.unpinAccount" : "wallet.pinAccount")}
        onClick={onTogglePinned}
      >
        <Icon name="star" size={15} />
      </button>
      <CopyButton
        className="icon-btn bare acct-copy"
        title={t("wallet.copy")}
        size={15}
        value={safe.address}
        onCopied={() => toast(t("common.copied"))}
      />
      <button
        className="icon-btn bare acct-row-edit"
        title={t("wallet.rename")}
        onClick={onRename}
      >
        <Icon name="edit" size={15} />
      </button>
      <button
        className="icon-btn bare acct-row-act"
        title={t("wallet.removeWatch")}
        onClick={onRemove}
      >
        <Icon name="trash" size={15} />
      </button>
    </div>
  );
}

function WalletGroup({
  wallet,
  accounts,
  active,
  t,
  renaming,
  pinnedSet,
  onRename,
  onRenameDone,
  onTogglePinned,
  onPick,
}: {
  wallet: WalletInfo;
  accounts: { addr: string; index: number }[];
  active: Account;
  t: TFn;
  renaming: boolean;
  pinnedSet: Set<string>;
  onRename: () => void;
  onRenameDone: () => void;
  onTogglePinned: (address: string) => void;
  onPick: (address: string) => void;
}) {
  const [name, setName] = useState(wallet.label);

  async function saveName() {
    const next = name.trim();
    if (next && next !== wallet.label) {
      await renameWallet(wallet.id, next);
      toast(t("wallet.renamed"));
    }
    onRenameDone();
  }

  return (
    <div className="acct-group">
      <div className="acct-group-head wallet">
        {renaming ? (
          <input
            className="input acct-rename"
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void saveName();
              if (e.key === "Escape") onRenameDone();
            }}
            onBlur={() => void saveName()}
          />
        ) : (
          <>
            <span className="wallet-label">
              {wallet.label}
              <KindBadge kind={wallet.kind} t={t} />
            </span>
            <div className="wallet-acts">
              <button
                className="icon-btn bare"
                title={t("wallet.rename")}
                onClick={onRename}
              >
                <Icon name="edit" size={14} />
              </button>
              <button
                className="icon-btn bare"
                title={t("wallet.delete")}
                onClick={async () => {
                  if (
                    await askConfirm({
                      title: t("wallet.deleteConfirm"),
                      message: t("wallet.deleteConfirmDetail"),
                      confirmLabel: t("wallet.delete"),
                      danger: true,
                    })
                  ) {
                    await deleteWallet(wallet.id);
                    toast(t("wallet.removed"));
                  }
                }}
              >
                <Icon name="trash" size={14} />
              </button>
            </div>
          </>
        )}
      </div>

      {accounts.map(({ addr, index }) => {
        const isPinned = pinnedSet.has(addr.toLowerCase());
        return (
          <div
            key={addr}
            className={`acct-row${addr === active.address ? " on" : ""}`}
          >
            <button className="acct-row-main" onClick={() => onPick(addr)}>
              <Avatar address={addr} size={30} />
              <div className="meta">
                <div className="l">
                  {wallet.accounts.length > 1
                    ? `${t("wallet.account")} ${index + 1}`
                    : shortAddress(addr, 12, 8)}
                </div>
                {wallet.accounts.length > 1 && (
                  <div className="a">{shortAddress(addr, 10, 6)}</div>
                )}
              </div>
              {addr === active.address && (
                <span className="check">
                  <Icon name="check" size={16} />
                </span>
              )}
            </button>
            <button
              className={`icon-btn bare acct-pin${isPinned ? " on" : ""}`}
              title={t(isPinned ? "wallet.unpinAccount" : "wallet.pinAccount")}
              onClick={() => onTogglePinned(addr)}
            >
              <Icon name="star" size={15} />
            </button>
            <CopyButton
              className="icon-btn bare acct-copy"
              title={t("wallet.copy")}
              size={15}
              value={addr}
              onCopied={() => toast(t("common.copied"))}
            />
          </div>
        );
      })}

      {wallet.kind === "hd" && (
        <button
          className="acct-add-account"
          onClick={() =>
            void addVaultAccount(wallet.id).then((addr) => {
              setActive(addr);
            })
          }
        >
          <Icon name="plus" size={14} /> {t("wallet.addAccount")}
        </button>
      )}
    </div>
  );
}

// ---- Add Wallet (create / import / connect Ledger / watch) -------------------

function pwScore(pw: string): number {
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9!@#$%^&*]/.test(pw)) s++;
  return Math.min(s, 4);
}
function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}

function isApproveResetRequiredError(e: unknown): boolean {
  const text = errText(e).toLowerCase();
  return (
    text.includes("eth_estimategas") ||
    text.includes("estimate gas") ||
    text.includes("gas estimate") ||
    text.includes("gas required exceeds allowance") ||
    text.includes("execution reverted") ||
    text.includes("not permitted") ||
    text.includes("code 3")
  );
}

type AddStep =
  | "menu"
  | "create"
  | "import"
  | "ledger"
  | "safe"
  | "watch"
  | "backup";

function AddWalletModal({
  hasPassword,
  onClose,
  onDone,
}: {
  hasPassword: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  const [step, setStep] = useState<AddStep>("menu");
  const [mnemonic, setMnemonic] = useState("");

  const opts: { s: AddStep; ic: IconName; label: string; coral?: boolean }[] = [
    { s: "create", ic: "plus", label: t("wallet.createWallet") },
    {
      s: "import",
      ic: "download",
      label: t("wallet.importWallet"),
      coral: true,
    },
    { s: "ledger", ic: "ledger", label: t("wallet.connectLedger") },
    { s: "safe", ic: "shield", label: t("safe.import") },
    { s: "watch", ic: "eye", label: t("wallet.watchAddress") },
  ];

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div
        className={`modal t-modal ${cls}${step === "ledger" ? " wide" : ""}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div className="modal-title">
            {step === "backup"
              ? t("wallet.backupNew")
              : t("wallet.addWalletTitle")}
          </div>
          <button className="icon-btn bare" onClick={close}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          {step === "menu" && (
            <div className="add-opts">
              {opts.map((o) => (
                <button
                  key={o.s}
                  className={`add-opt${o.coral ? " coral" : ""}`}
                  onClick={() => setStep(o.s)}
                >
                  <span className="add-opt-ic">
                    <Icon name={o.ic} size={19} />
                  </span>
                  <span className="add-opt-label">{o.label}</span>
                  <Icon name="chevronR" size={16} />
                </button>
              ))}
            </div>
          )}
          {step === "create" && (
            <CreateWalletForm
              needsPassword={!hasPassword}
              onBack={() => setStep("menu")}
              onCreated={(m) => {
                setMnemonic(m);
                setStep("backup");
              }}
            />
          )}
          {step === "import" && (
            <ImportWalletForm
              needsPassword={!hasPassword}
              onBack={() => setStep("menu")}
              onDone={onDone}
            />
          )}
          {step === "ledger" && (
            <LedgerForm onBack={() => setStep("menu")} onDone={onDone} />
          )}
          {step === "safe" && (
            <SafeForm onBack={() => setStep("menu")} onDone={onDone} />
          )}
          {step === "watch" && (
            <WatchForm onBack={() => setStep("menu")} onDone={onDone} />
          )}
          {step === "backup" && (
            <BackupBox mnemonic={mnemonic} onDone={onDone} />
          )}
        </div>
      </div>
    </div>
  );
}

function PasswordPair({
  pw,
  setPw,
  confirm,
  setConfirm,
  t,
}: {
  pw: string;
  setPw: (v: string) => void;
  confirm: string;
  setConfirm: (v: string) => void;
  t: TFn;
}) {
  const score = pwScore(pw);
  return (
    <>
      <div className="add-note">{t("wallet.setPasswordHint")}</div>
      <div className="field">
        <label className="field-label">{t("lock.newPassword")}</label>
        <input
          className="input"
          type="password"
          value={pw}
          placeholder={t("lock.min8")}
          onChange={(e) => setPw(e.target.value)}
        />
        <div className={`pw-strength s${score}`}>
          <i />
          <i />
          <i />
          <i />
        </div>
      </div>
      <div className="field">
        <label className="field-label">{t("lock.confirm")}</label>
        <input
          className="input"
          type="password"
          value={confirm}
          placeholder={t("lock.confirm")}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </div>
    </>
  );
}

function CreateWalletForm({
  needsPassword,
  onBack,
  onCreated,
}: {
  needsPassword: boolean;
  onBack: () => void;
  onCreated: (mnemonic: string) => void;
}) {
  const { t } = useT();
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (needsPassword) {
      if (pw.length < 8) return setError(t("lock.errShort"));
      if (pw !== confirm) return setError(t("lock.errMatch"));
    }
    setBusy(true);
    setError(null);
    try {
      const { mnemonic, address } = await createVault(
        needsPassword ? pw : undefined,
      );
      setActive(address); // make the new wallet active everywhere (shell + backend + dApps)
      toast(t("wallet.added"));
      onCreated(mnemonic);
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  }

  return (
    <div className="add-form">
      {needsPassword ? (
        <PasswordPair
          pw={pw}
          setPw={setPw}
          confirm={confirm}
          setConfirm={setConfirm}
          t={t}
        />
      ) : (
        <div className="add-note">{t("lock.optCreateDesc")}</div>
      )}
      {error && (
        <div className="lock-err">
          <Icon name="alert" size={16} /> {error}
        </div>
      )}
      <div className="add-acts">
        <button className="btn btn-ghost btn-sm" onClick={onBack}>
          {t("lock.back")}
        </button>
        <button
          className="btn btn-aurora btn-sm"
          disabled={busy}
          onClick={submit}
        >
          {busy ? "…" : t("wallet.createWallet")}
        </button>
      </div>
    </div>
  );
}

export function ImportWalletForm({
  needsPassword,
  onBack,
  onDone,
}: {
  needsPassword: boolean;
  onBack: () => void;
  onDone: () => void;
}) {
  const { t } = useT();
  const [tab, setTab] = useState<"phrase" | "privkey">("phrase");
  const segRef = useSegPill<HTMLDivElement>(tab);
  const [phrase, setPhrase] = useState("");
  const [privkey, setPrivkey] = useState("");
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (tab === "phrase") {
      const words = phrase.trim().split(/\s+/).length;
      if (words !== 12 && words !== 24) return setError(t("lock.errPhrase"));
    } else {
      const body = privkey.trim().replace(/^0x/i, "");
      if (!/^[0-9a-fA-F]{64}$/.test(body))
        return setError(t("lock.errPrivkey"));
    }
    if (needsPassword) {
      if (pw.length < 8) return setError(t("lock.errShort"));
      if (pw !== confirm) return setError(t("lock.errMatch"));
    }
    setBusy(true);
    setError(null);
    try {
      const ref =
        tab === "phrase"
          ? await importVault(needsPassword ? pw : undefined, phrase, name)
          : await importPrivateKey(needsPassword ? pw : undefined, privkey, name);
      setActive(ref.address); // make the imported wallet active everywhere
      toast(t("wallet.added"));
      onDone();
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  }

  return (
    <div className="add-form">
      <div className="seg lock-seg" ref={segRef}>
        <span className="t-tabs-pill" aria-hidden="true" />
        <button
          className={tab === "phrase" ? "on" : ""}
          onClick={() => setTab("phrase")}
        >
          {t("lock.importTab.phrase")}
        </button>
        <button
          className={tab === "privkey" ? "on" : ""}
          onClick={() => setTab("privkey")}
        >
          {t("lock.importTab.privkey")}
        </button>
      </div>
      <WalletNameField value={name} onChange={setName} disabled={busy} />
      {tab === "phrase" ? (
        <textarea
          className="textarea mono"
          rows={3}
          value={phrase}
          onChange={(e) => setPhrase(e.target.value)}
          placeholder={t("lock.phrasePlaceholder")}
        />
      ) : (
        <textarea
          className="textarea mono"
          rows={2}
          value={privkey}
          onChange={(e) => setPrivkey(e.target.value)}
          placeholder={t("lock.privkeyPlaceholder")}
        />
      )}
      {needsPassword && (
        <PasswordPair
          pw={pw}
          setPw={setPw}
          confirm={confirm}
          setConfirm={setConfirm}
          t={t}
        />
      )}
      {error && (
        <div className="lock-err">
          <Icon name="alert" size={16} /> {error}
        </div>
      )}
      <div className="add-acts">
        <button className="btn btn-ghost btn-sm" onClick={onBack}>
          {t("lock.back")}
        </button>
        <button
          className="btn btn-aurora btn-sm"
          disabled={busy}
          onClick={submit}
        >
          {busy
            ? "…"
            : tab === "phrase"
              ? t("lock.import")
              : t("lock.importPrivkey")}
        </button>
      </div>
    </div>
  );
}

export function LedgerForm({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: () => void;
}) {
  const { t } = useT();
  const [name, setName] = useState("");
  const {
    accounts,
    page,
    loading,
    connecting,
    started,
    error,
    scan,
    nextPage,
    prevPage,
    pick,
  } = useLedgerScan((ref) => {
    setActive(ref.address); // make the connected Ledger account active everywhere
    toast(t("wallet.added"));
    onDone();
  }, name);
  const showList = started && (accounts.length > 0 || loading);

  return (
    <div className="add-form">
      <WalletNameField value={name} onChange={setName} disabled={connecting} />
      {showList ? (
        <LedgerList
          accounts={accounts}
          page={page}
          loading={loading}
          connecting={connecting}
          onPick={pick}
          onPrev={prevPage}
          onNext={nextPage}
        />
      ) : (
        <div className="add-note">
          {connecting ? t("lock.ledgerConnecting") : t("lock.ledgerIntro")}
        </div>
      )}
      {error && (
        <div className="lock-err">
          <Icon name="alert" size={16} /> {error}
        </div>
      )}
      <div className="add-acts">
        <button className="btn btn-ghost btn-sm" onClick={onBack}>
          {t("lock.back")}
        </button>
        {!showList && (
          <button
            className="btn btn-aurora btn-sm"
            disabled={loading}
            onClick={scan}
          >
            {loading ? "…" : error ? t("lock.retry") : t("lock.ledgerScan")}
          </button>
        )}
      </div>
    </div>
  );
}

function SafeForm({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: () => void;
}) {
  const { t } = useT();
  const chains = useChains();
  const vault = useVault();
  const active = useActiveAccount();
  const accounts = useAccounts();
  const [chainId, setChainId] = useState(chains[0]?.id ?? "0x1");
  const [address, setAddress] = useState("");
  const [label, setLabel] = useState("");
  const [serviceUrl, setServiceUrl] = useState(
    defaultSafeServiceUrl(chains[0]?.id ?? "0x1") ?? "",
  );
  const [info, setInfo] = useState<SafeInfo | null>(null);
  const [ownerAddress, setOwnerAddress] = useState("");
  const [localOwners, setLocalOwners] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function changeChain(next: string) {
    setChainId(next);
    setServiceUrl(defaultSafeServiceUrl(next) ?? "");
    setInfo(null);
    setOwnerAddress("");
    setLocalOwners([]);
    setError(null);
  }

  async function inspect() {
    const trimmed = address.trim();
    if (!isAddress(trimmed)) {
      setError(t("safe.invalidAddress"));
      return;
    }
    if (
      accounts.some(
        (account) => account.address.toLowerCase() === trimmed.toLowerCase(),
      )
    ) {
      setError(t("safe.alreadyAdded"));
      return;
    }
    setBusy(true);
    setError(null);
    try {
      let inspected = await inspectSafe(chainId, trimmed);
      const signerAddresses = vault.wallets.flatMap((wallet) => wallet.accounts);
      // Browser preview has no contract RPC. Use the public demo signer list so
      // the import UI remains testable without pretending a real Safe exists.
      if (!isTauri() && inspected.owners.length === 0) {
        inspected = { ...inspected, owners: signerAddresses, threshold: 1 };
      }
      const matches = inspected.owners.filter((owner) =>
        signerAddresses.some(
          (signer) => signer.toLowerCase() === owner.toLowerCase(),
        ),
      );
      if (matches.length === 0) {
        throw new Error(t("safe.noLocalOwner"));
      }
      const preferred = matches.find(
        (owner) => owner.toLowerCase() === active.address.toLowerCase(),
      );
      setInfo(inspected);
      setLocalOwners(matches);
      setOwnerAddress(preferred ?? matches[0]);
    } catch (cause) {
      setError(errText(cause));
    } finally {
      setBusy(false);
    }
  }

  function saveSafe() {
    if (!info) {
      setError(t("safe.inspectFirst"));
      return;
    }
    if (!ownerAddress) {
      setError(t("safe.selectOwner"));
      return;
    }
    if (!serviceUrl.trim()) {
      setError(t("safe.serviceRequired"));
      return;
    }
    try {
      const safe = addSafeAccount(info, ownerAddress, serviceUrl, label);
      setActive(safe.address);
      toast(t("safe.imported"));
      onDone();
    } catch (cause) {
      setError(errText(cause));
    }
  }

  return (
    <div className="add-form">
      <div className="field">
        <label className="field-label">{t("approval.network")}</label>
        <select
          className="input"
          value={chainId}
          onChange={(event) => changeChain(event.target.value)}
        >
          {chains.map((chain) => (
            <option key={chain.id} value={chain.id}>
              {chain.name}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label className="field-label">{t("safe.address")}</label>
        <input
          className="input mono"
          autoFocus
          value={address}
          placeholder={t("wallet.pasteAddr")}
          onChange={(event) => {
            setAddress(event.target.value);
            setInfo(null);
            setError(null);
          }}
        />
      </div>
      <WalletNameField value={label} onChange={setLabel} placeholder={t("safe.namePlaceholder")} disabled={busy} />
      <div className="field">
        <label className="field-label">{t("safe.serviceUrl")}</label>
        <input
          className="input mono"
          value={serviceUrl}
          placeholder="https://…/api"
          onChange={(event) => {
            setServiceUrl(event.target.value);
            setError(null);
          }}
        />
        <div className="add-note">{t("safe.serviceHint")}</div>
      </div>

      {info && (
        <div className="safe-import-summary">
          <div>
            <span>{t("safe.thresholdLabel")}</span>
            <b>
              {info.threshold}/{info.owners.length}
            </b>
          </div>
          <div>
            <span>{t("safe.nonce")}</span>
            <b className="mono">{BigInt(info.nonce).toString()}</b>
          </div>
          <div className="field">
            <label className="field-label">{t("safe.localOwner")}</label>
            <select
              className="input mono"
              value={ownerAddress}
              onChange={(event) => setOwnerAddress(event.target.value)}
            >
              {localOwners.map((owner) => (
                <option key={owner} value={owner}>
                  {owner}
                </option>
              ))}
            </select>
          </div>
        </div>
      )}

      {error && (
        <div className="lock-err">
          <Icon name="alert" size={16} /> {error}
        </div>
      )}
      <div className="add-acts">
        <button className="btn btn-ghost btn-sm" onClick={onBack}>
          {t("lock.back")}
        </button>
        {info ? (
          <button className="btn btn-primary btn-sm" onClick={saveSafe}>
            {t("safe.import")}
          </button>
        ) : (
          <button
            className="btn btn-aurora btn-sm"
            disabled={busy || !address.trim()}
            onClick={() => void inspect()}
          >
            {busy ? "…" : t("safe.inspect")}
          </button>
        )}
      </div>
    </div>
  );
}

export function WatchForm({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: () => void;
}) {
  const { t } = useT();
  const [val, setVal] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState<string | null>(null);

  function submit() {
    try {
      addWatchAccount(val, name);
      toast(t("wallet.added"));
      onDone();
    } catch (e) {
      setError(errText(e));
    }
  }

  return (
    <div className="add-form">
      <div className="field">
        <label className="field-label">{t("wallet.watchAddress")}</label>
        <input
          className="input mono"
          autoFocus
          value={val}
          placeholder={t("wallet.pasteAddr")}
          onChange={(e) => {
            setVal(e.target.value);
            setError(null);
          }}
          onKeyDown={(e) => e.key === "Enter" && submit()}
        />
      </div>
      <WalletNameField value={name} onChange={setName} />
      {error && (
        <div className="lock-err">
          <Icon name="alert" size={16} /> {error}
        </div>
      )}
      <div className="add-acts">
        <button className="btn btn-ghost btn-sm" onClick={onBack}>
          {t("lock.back")}
        </button>
        <button
          className="btn btn-primary btn-sm"
          disabled={!val}
          onClick={submit}
        >
          {t("wallet.add")}
        </button>
      </div>
    </div>
  );
}

function BackupBox({
  mnemonic,
  onDone,
}: {
  mnemonic: string;
  onDone: () => void;
}) {
  const { t } = useT();
  const [revealed, setRevealed] = useState(false);
  const [acked, setAcked] = useState(false);
  const words = mnemonic.trim().split(/\s+/);
  return (
    <div className="add-form">
      <div className="warn-box">
        <Icon name="alert" size={16} /> {t("lock.backupWarn")}
      </div>
      <div style={{ position: "relative" }}>
        <ol className={`mnemonic${revealed ? "" : " blurred"}`}>
          {words.map((w, i) => (
            <li key={i}>
              <span className="n">{i + 1}</span>
              {w}
            </li>
          ))}
        </ol>
        {!revealed && (
          <div className="reveal-mnemonic" onClick={() => setRevealed(true)}>
            <span className="pill">
              <Icon name="eye" size={15} /> {t("lock.tapReveal")}
            </span>
          </div>
        )}
      </div>
      <label className="lock-check">
        <input
          type="checkbox"
          checked={acked}
          onChange={(e) => setAcked(e.target.checked)}
        />
        {t("lock.backupAck")}
      </label>
      <button
        className="btn btn-aurora btn-block"
        disabled={!acked}
        onClick={onDone}
      >
        {t("lock.continue")}
      </button>
    </div>
  );
}

function ReceiveModal({
  account,
  onClose,
}: {
  account: Account;
  onClose: () => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div className={`modal t-modal ${cls}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{t("wallet.receive")}</div>
          <button className="icon-btn bare" onClick={close}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          <div className="receive-id">
            <Avatar address={account.address} size={26} />
            <span className="nm">{account.label}</span>
          </div>
          <div className="receive-qr">
            <QrCode value={account.address} size={208} />
          </div>
          <div className="addr-box">
            <span className="a">{account.address}</span>
            <CopyButton
              className="icon-btn"
              title={t("wallet.copy")}
              value={account.address}
              onCopied={() => toast(t("common.copied"))}
            />
          </div>
          <div className="receive-hint">
            <Icon name="info" size={16} /> {t("wallet.receiveHint")}
          </div>
        </div>
      </div>
    </div>
  );
}

// Add a custom ERC-20 (#8): pick a chain, paste the contract address, scan its
// on-chain metadata, then persist it. Already-added customs are listed with a
// remove control.
function AddTokenModal({
  defaultChain,
  onClose,
}: {
  defaultChain?: string;
  onClose: () => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  const chains = useChains();
  const custom = useCustomTokens();
  const [chainId, setChainId] = useState<string>(
    defaultChain ?? chains[0]?.id ?? "0x1",
  );
  const [addr, setAddr] = useState("");
  const [scanned, setScanned] = useState<TokenMeta | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const customList = useMemo(() => {
    const out: { chainId: string; token: TokenMeta }[] = [];
    for (const [cid, list] of Object.entries(custom)) {
      for (const tk of list) out.push({ chainId: cid, token: tk });
    }
    return out;
  }, [custom]);

  function reset() {
    setScanned(null);
    setError(null);
  }
  async function scan() {
    const a = addr.trim();
    if (!isAddress(a)) return setError(t("wallet.invalidAddress"));
    setBusy(true);
    reset();
    try {
      setScanned(await fetchTokenMeta(chainId, a));
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }
  function add() {
    if (!scanned) return;
    addCustomToken(chainId, scanned);
    toast(t("wallet.tokenAdded"));
    setAddr("");
    setScanned(null);
  }

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div className={`modal t-modal ${cls}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{t("wallet.addToken")}</div>
          <button className="icon-btn bare" onClick={close}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          <div className="add-form">
            <div className="field">
              <label className="field-label">{t("wallet.network")}</label>
              <select
                className="input"
                value={chainId}
                onChange={(e) => {
                  setChainId(e.target.value);
                  reset();
                }}
              >
                {chains.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label className="field-label">{t("wallet.tokenAddress")}</label>
              <div className="scan-row">
                <input
                  className="input mono"
                  value={addr}
                  placeholder="0x…"
                  onChange={(e) => {
                    setAddr(e.target.value);
                    reset();
                  }}
                  onKeyDown={(e) => e.key === "Enter" && void scan()}
                />
                <button
                  className="btn btn-ghost btn-sm"
                  disabled={busy || !addr.trim()}
                  onClick={() => void scan()}
                >
                  {busy ? t("wallet.scanning") : t("wallet.scan")}
                </button>
              </div>
            </div>
            {error && (
              <div className="lock-err">
                <Icon name="alert" size={16} /> {error}
              </div>
            )}
            {scanned && (
              <div className="scan-preview">
                <Coin
                  symbol={scanned.symbol}
                  color={seedColor(scanned.address)}
                  logo={scanned.logo || undefined}
                  size={36}
                />
                <div className="scan-meta">
                  <div className="l">
                    {scanned.symbol}{" "}
                    <span className="muted">· {scanned.name}</span>
                  </div>
                  <div className="a">
                    {shortAddress(scanned.address, 10, 8)} · {scanned.decimals}{" "}
                    decimals
                  </div>
                </div>
                <button className="btn btn-aurora btn-sm" onClick={add}>
                  {t("wallet.add")}
                </button>
              </div>
            )}
          </div>

          {customList.length > 0 && (
            <div className="custom-list">
              <div className="custom-list-head">{t("wallet.customTokens")}</div>
              {customList.map(({ chainId: cid, token }) => (
                <div key={`${cid}:${token.address}`} className="custom-row">
                  <Coin
                    symbol={token.symbol}
                    color={seedColor(token.address)}
                    logo={token.logo || undefined}
                    size={28}
                  />
                  <div className="custom-meta">
                    <div className="l">{token.symbol}</div>
                    <div className="a">
                      {findChain(cid)?.name ?? cid} ·{" "}
                      {shortAddress(token.address, 8, 6)}
                    </div>
                  </div>
                  <button
                    className="icon-btn bare"
                    title={t("wallet.removeToken")}
                    onClick={() => {
                      removeCustomToken(cid, token.address);
                      toast(t("wallet.removed"));
                    }}
                  >
                    <Icon name="trash" size={15} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Wallet-initiated Send (#7): pick a held asset (native or ERC-20), recipient, and
// amount; the actual confirm (with gas details) happens in the approval window.
function resolveRecipient(input: string): string | null {
  const raw = input.trim();
  if (isAddress(raw)) return raw;
  return null;
}

function AssetSelect({
  assets,
  selected,
  onChange,
}: {
  assets: SendAsset[];
  selected: SendAsset | undefined;
  onChange: (key: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const current = selected ?? assets[0];
  if (!current) return null;

  function pick(key: string) {
    onChange(key);
    setOpen(false);
  }

  return (
    <div className="asset-select">
      <button
        className="asset-trigger"
        type="button"
        onClick={() => setOpen((o) => !o)}
      >
        <Coin
          symbol={current.symbol}
          color={current.color}
          logo={current.logo}
          size={34}
        />
        <span className="asset-trigger-meta">
          <span className="asset-symbol">{current.symbol}</span>
          <span className="asset-sub">{current.chainName}</span>
        </span>
        <span className="asset-balance">
          {fmtUnitsDisplay(current.wei, current.decimals)} {current.symbol}
        </span>
        <Icon name="chevronD" size={16} />
      </button>

      {open && (
        <>
          <div className="asset-backdrop" onClick={() => setOpen(false)} />
          <div className="asset-menu">
            {assets.map((asset) => (
              <button
                key={asset.key}
                type="button"
                className={`asset-option${asset.key === current.key ? " on" : ""}`}
                onClick={() => pick(asset.key)}
              >
                <Coin
                  symbol={asset.symbol}
                  color={asset.color}
                  logo={asset.logo}
                  size={32}
                />
                <span className="asset-option-meta">
                  <span>
                    {asset.symbol}
                    <span className="muted"> · {asset.chainName}</span>
                  </span>
                  <span>
                    {asset.kind === "erc20" && asset.address
                      ? shortAddress(asset.address, 8, 6)
                      : asset.chainName}
                  </span>
                </span>
                <span className="asset-option-balance">
                  {fmtUnitsDisplay(asset.wei, asset.decimals)} {asset.symbol}
                </span>
                {asset.key === current.key && <Icon name="check" size={16} />}
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function swapInitialSlots(): QuoteSlot[] {
  return PROVIDERS.map((p) => ({
    providerId: p.id,
    displayName: p.displayName,
    loading: false,
    quote: null,
    error: null,
    unsupported: false,
  }));
}

function swapLoadingSlots(): QuoteSlot[] {
  return PROVIDERS.map((p) => ({
    providerId: p.id,
    displayName: p.displayName,
    loading: true,
    quote: null,
    error: null,
    unsupported: false,
  }));
}

function numericChainId(chainId: string): number | null {
  try {
    return chainId.startsWith("0x") ? parseInt(chainId, 16) : Number(chainId);
  } catch {
    return null;
  }
}

function numberToChainId(chainId: number): string {
  return `0x${chainId.toString(16)}`;
}

function tokenKeyOf(token: ProviderToken): string {
  return token.address.toLowerCase();
}

function nativeTokenAddress(address?: string): string {
  return address?.toLowerCase() || NATIVE_TOKEN_ADDRESS;
}

function sendAssetToProviderToken(
  asset: SendAsset,
  chainId: number,
  tokensByChain: Map<number, MergedToken[]>,
): ProviderToken {
  const wanted = asset.kind === "native" ? NATIVE_TOKEN_ADDRESS : nativeTokenAddress(asset.address);
  const supported = (tokensByChain.get(chainId) ?? []).find(
    (tk) => tk.address.toLowerCase() === wanted,
  );
  if (supported) return supported;
  return {
    chainId,
    address: wanted,
    symbol: asset.symbol,
    name: asset.symbol,
    decimals: asset.decimals,
    logo: asset.logo ?? "",
  };
}

function swapTokenProviders(token: ProviderToken | MergedToken | null | undefined): ProviderId[] | undefined {
  const providers = (token as Partial<MergedToken> | null | undefined)?.providers;
  return Array.isArray(providers) ? providers : undefined;
}

function cleanDecimal(value: string): string {
  const cleaned = value.replace(/[^0-9.]/g, "");
  const dot = cleaned.indexOf(".");
  return dot === -1
    ? cleaned
    : cleaned.slice(0, dot + 1) + cleaned.slice(dot + 1).replace(/\./g, "");
}


function trimAmount(s: string, maxDecimals: number): string {
  const n = Number.parseFloat(s);
  if (!Number.isFinite(n)) return s;
  if (n === 0) return "0";
  if (n >= 1) return n.toLocaleString("en-US", { maximumFractionDigits: 4 });
  return n.toFixed(maxDecimals).replace(/\.?0+$/, "");
}

function normalizeTxValue(value: string | undefined): string {
  if (!value || value === "0") return "0x0";
  if (value.startsWith("0x")) return value;
  try {
    return toHexQuantity(BigInt(value));
  } catch {
    return "0x0";
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

async function waitForTxSuccess(chainId: string, hash: string, label: string): Promise<void> {
  if (!isTauri()) return;
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const receipt = await rpc<{ status?: string } | null>(chainId, "eth_getTransactionReceipt", [hash]);
    if (receipt) {
      if (receipt.status === "0x1") return;
      throw new Error(`${label} transaction failed on-chain`);
    }
    await sleep(2_500);
  }
  throw new Error(`${label} transaction is still pending. Wait for it to confirm before swapping.`);
}

function encodeErc20Approve(spender: string, amount: bigint): string {
  const addr = spender.toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{40}$/.test(addr)) throw new Error("invalid spender");
  return `0x095ea7b3${addr.padStart(64, "0")}${amount.toString(16).padStart(64, "0")}`;
}

function providerName(id: ProviderId): string {
  return PROVIDERS.find((p) => p.id === id)?.displayName ?? id;
}

async function pollSwapStatus(
  params: QuoteParams,
  hash: string,
  providerId: ProviderId,
  requestId: string | undefined,
  setStatus: (status: NeutralStatus) => void,
) {
  const provider = getProvider(providerId);
  for (let i = 0; i < 60; i++) {
    try {
      const status = await provider.getStatus({ params, sourceHash: hash, requestId });
      setStatus(status);
      if (status.state !== "pending") return;
    } catch {
      // Source txs often take a few blocks to be indexed by swap providers.
    }
    await new Promise((r) => window.setTimeout(r, 5000));
  }
}

function QuoteChooser({
  slots,
  selectedProvider,
  toSymbol,
  onSelect,
}: {
  slots: QuoteSlot[];
  selectedProvider: ProviderId | null;
  toSymbol: string;
  onSelect: (id: ProviderId) => void;
}) {
  const best = pickBestSlot(slots)?.providerId ?? null;
  return (
    <div className="swap-quotes">
      {slots.map((slot) => (
        <button
          key={slot.providerId}
          className={`swap-quote${slot.providerId === selectedProvider ? " on" : ""}`}
          disabled={!slot.quote}
          onClick={() => slot.quote && onSelect(slot.providerId)}
        >
          <span className="swap-quote-head">
            <b>{slot.displayName}</b>
            {best === slot.providerId && slot.quote && <i>Best</i>}
          </span>
          {slot.loading ? (
            <span className="swap-quote-muted">Fetching…</span>
          ) : slot.unsupported ? (
            <span className="swap-quote-muted">Unsupported</span>
          ) : slot.error ? (
            <span className="swap-quote-error" title={slot.error}>{slot.error}</span>
          ) : slot.quote ? (
            <>
              <span className="swap-quote-amount">
                {trimAmount(slot.quote.amountOut, 8)} {toSymbol}
              </span>
              <span className="swap-quote-muted">
                {slot.quote.estimatedTimeSeconds != null
                  ? `~${Math.max(1, Math.round(slot.quote.estimatedTimeSeconds / 60))}m`
                  : slot.quote.routeDescription}
              </span>
            </>
          ) : (
            <span className="swap-quote-muted">—</span>
          )}
        </button>
      ))}
    </div>
  );
}

/** One tx hash in the swap status card — a link to that chain's explorer when we
 *  know one, plain mono text when we don't. */
function SwapStatusHash({
  label,
  hash,
  chainId,
  chainName,
  t,
}: {
  label?: string;
  hash: string;
  chainId: string;
  chainName: string;
  t: TFn;
}) {
  const href = explorerTxUrl(findChain(chainId), chainId, chainName, hash);
  const text = shortAddress(hash, 10, 8);
  return (
    <div className="swap-status-sub">
      {label && <span className="swap-status-hash-label">{label}: </span>}
      {href ? (
        <button
          type="button"
          className="swap-status-hash mono"
          title={`${t("wallet.openExplorer")} · ${chainName}`}
          onClick={() => void openExternalUrl(href)}
        >
          {text}
          <Icon name="external" size={12} />
        </button>
      ) : (
        <span className="mono" title={t("wallet.noExplorer")}>
          {text}
        </span>
      )}
    </div>
  );
}

function SwapStatusView({
  status,
  hash,
  provider,
  fromChainId,
  fromChainName,
  toChainId,
  toChainName,
  t,
}: {
  status: NeutralStatus | null;
  hash: string;
  provider: ProviderId;
  fromChainId: string;
  fromChainName: string;
  toChainId: string;
  toChainName: string;
  t: TFn;
}) {
  const done = status?.state === "success";
  const failed = status?.state === "failed" || status?.state === "refunded";
  const pending = !done && !failed;
  return (
    <div
      className={`swap-status-card${done ? " done" : failed ? " failed" : " pending"}`}
      role="status"
      aria-live="polite"
    >
      <span className="swap-status-ic" aria-hidden="true">
        {pending ? <span /> : done ? <Icon name="check" size={16} /> : <Icon name="alert" size={16} />}
      </span>
      <div className="swap-status-main">
        <div className="swap-status-title">
          {done
            ? t("wallet.swapComplete")
            : failed
              ? status?.message || t("wallet.swapFailed")
              : t("wallet.swapTracking", { provider: providerName(provider) })}
        </div>
        <SwapStatusHash
          hash={status?.sourceHash ?? hash}
          chainId={fromChainId}
          chainName={fromChainName}
          t={t}
        />
        {status?.destHash && (
          <SwapStatusHash
            label={t("wallet.received")}
            hash={status.destHash}
            chainId={toChainId}
            chainName={toChainName}
            t={t}
          />
        )}
      </div>
      {pending && <div className="swap-status-bar" aria-hidden="true" />}
    </div>
  );
}

function SwapAssetButton({
  token,
  chainName,
  chainLogo,
  balance,
  providers,
  placeholder,
  onClick,
}: {
  token: ProviderToken | MergedToken | null;
  chainName?: string;
  chainLogo?: string;
  balance?: string;
  providers?: ProviderId[];
  placeholder: string;
  onClick: () => void;
}) {
  return (
    <button type="button" className="swap-asset-btn" onClick={onClick}>
      {token ? (
        <>
          <SwapLogo url={token.logo} fallback={token.symbol} size={34} />
          <span className="swap-asset-copy">
            <span className="swap-asset-symbol">{token.symbol}</span>
            <span className="swap-asset-chain">
              <SwapLogo url={chainLogo} fallback={chainName ?? token.symbol} size={14} />
              {chainName}
              {providers && <SwapProviderBadges providers={providers} />}
            </span>
          </span>
          {balance && <span className="swap-asset-balance">{balance}</span>}
        </>
      ) : (
        <span className="swap-asset-placeholder">{placeholder}</span>
      )}
      <Icon name="chevronDown" size={16} />
    </button>
  );
}

function SwapAssetPicker({
  title,
  items,
  selectedKey,
  t,
  onPick,
  onClose,
}: {
  title: string;
  items: SwapPickerItem[];
  selectedKey: string;
  t: TFn;
  onPick: (item: SwapPickerItem) => void;
  onClose: () => void;
}) {
  const [chainQuery, setChainQuery] = useState("");
  const [tokenQuery, setTokenQuery] = useState("");
  const selected = items.find((item) => item.key === selectedKey);
  const chainIds = useMemo(() => {
    const map = new Map<number, SwapPickerItem>();
    for (const item of items) {
      if (!map.has(item.chainId)) map.set(item.chainId, item);
    }
    return [...map.values()].sort((a, b) => a.chainName.localeCompare(b.chainName));
  }, [items]);
  const [selectedChainId, setSelectedChainId] = useState<number | null>(
    selected?.chainId ?? chainIds[0]?.chainId ?? null,
  );

  useEffect(() => {
    if (selectedChainId && chainIds.some((c) => c.chainId === selectedChainId)) return;
    setSelectedChainId(selected?.chainId ?? chainIds[0]?.chainId ?? null);
  }, [chainIds, selected?.chainId, selectedChainId]);

  const visibleChains = useMemo(() => {
    const q = chainQuery.trim().toLowerCase();
    return chainIds.filter((item) => !q || item.chainName.toLowerCase().includes(q));
  }, [chainIds, chainQuery]);

  const visibleTokens = useMemo(() => {
    const q = tokenQuery.trim().toLowerCase();
    const addrSearch = q.startsWith("0x");
    return items
      .filter((item) => !selectedChainId || item.chainId === selectedChainId)
      .filter((item) => {
        if (!q) return true;
        const token = item.token;
        return (
          token.symbol.toLowerCase().includes(q) ||
          token.name.toLowerCase().includes(q) ||
          (addrSearch && token.address.toLowerCase().includes(q))
        );
      })
      .sort((a, b) => a.token.symbol.localeCompare(b.token.symbol));
  }, [items, selectedChainId, tokenQuery]);

  return (
    <div className="swap-picker-layer" onClick={onClose}>
      <div className="swap-picker-panel" onClick={(e) => e.stopPropagation()}>
        <div className="swap-picker-head">
          <div className="swap-picker-title">{title}</div>
          <button className="icon-btn bare" onClick={onClose}>
            <Icon name="close" size={17} />
          </button>
        </div>
        <div className="swap-picker-body">
          <aside className="swap-picker-chains">
            <label className="swap-picker-search">
              <Icon name="search" size={14} />
              <input
                value={chainQuery}
                onChange={(e) => setChainQuery(e.target.value)}
                placeholder={t("wallet.searchChains")}
              />
            </label>
            <div className="swap-picker-chain-list">
              {visibleChains.map((item) => (
                <button
                  key={item.chainId}
                  type="button"
                  className={`swap-picker-chain${item.chainId === selectedChainId ? " on" : ""}`}
                  onClick={() => setSelectedChainId(item.chainId)}
                >
                  <SwapLogo
                    url={item.chainLogo}
                    fallback={item.chainSymbol ?? item.chainName}
                    size={22}
                  />
                  <span>{item.chainName}</span>
                </button>
              ))}
            </div>
          </aside>
          <section className="swap-picker-tokens">
            <label className="swap-picker-search wide">
              <Icon name="search" size={14} />
              <input
                value={tokenQuery}
                onChange={(e) => setTokenQuery(e.target.value)}
                placeholder={t("wallet.searchTokens")}
                autoFocus
              />
            </label>
            <div className="swap-picker-token-list">
              {visibleTokens.length === 0 ? (
                <div className="swap-picker-empty">{t("wallet.noTokensFound")}</div>
              ) : (
                visibleTokens.slice(0, 180).map((item) => (
                  <button
                    key={item.key}
                    type="button"
                    className={`swap-picker-token${item.key === selectedKey ? " on" : ""}`}
                    onClick={() => onPick(item)}
                  >
                    <SwapLogo url={item.token.logo} fallback={item.token.symbol} size={36} />
                    <span className="swap-picker-token-main">
                      <span className="swap-picker-token-top">
                        <strong>{item.token.symbol}</strong>
                        {item.providers && <SwapProviderBadges providers={item.providers} />}
                      </span>
                      <span className="swap-picker-token-sub">
                        {item.chainName}
                        <span>{shortAddress(item.token.address, 6, 4)}</span>
                      </span>
                    </span>
                    {item.balance && <span className="swap-picker-balance">{item.balance}</span>}
                    {item.key === selectedKey && <Icon name="check" size={16} />}
                  </button>
                ))
              )}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function SwapLogo({
  url,
  fallback,
  size,
}: {
  url?: string;
  fallback: string;
  size: number;
}) {
  return (
    <span className="swap-logo" style={{ width: size, height: size, fontSize: Math.max(9, size * 0.34) }}>
      {url ? <img src={url} alt="" /> : fallback.slice(0, 2).toUpperCase()}
    </span>
  );
}

function SwapProviderBadges({ providers }: { providers: ProviderId[] }) {
  return (
    <span className="swap-provider-badges">
      {providers.includes("xflows") && <span className="x">X</span>}
      {providers.includes("relay") && <span className="r">R</span>}
    </span>
  );
}


function CrossChainModal({
  assets,
  initialAssetKey,
  activeAddress,
  onClose,
}: {
  assets: SendAsset[];
  initialAssetKey?: string;
  activeAddress: string;
  onClose: () => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  const [sel, setSel] = useState<string>(
    initialAssetKey && assets.some((a) => a.key === initialAssetKey)
      ? initialAssetKey
      : (assets[0]?.key ?? ""),
  );
  const [amount, setAmount] = useState("");
  const [slippage, setSlippage] = useState(0.01);
  const [supportedChains, setSupportedChains] = useState<MergedChain[]>([]);
  const [tokensByChain, setTokensByChain] = useState<Map<number, MergedToken[]>>(new Map());
  const [targetChainId, setTargetChainId] = useState<number | null>(null);
  const [targetTokenKey, setTargetTokenKey] = useState("");
  const [pickerMode, setPickerMode] = useState<SwapPickerMode | null>(null);
  const [quoteSlots, setQuoteSlots] = useState<QuoteSlot[]>(() => swapInitialSlots());
  const [selectedProvider, setSelectedProvider] = useState<ProviderId | null>(null);
  const [userPickedProvider, setUserPickedProvider] = useState(false);
  const [approved, setApproved] = useState<Set<string>>(() => new Set());
  const [stage, setStage] = useState<SwapStage>({ kind: "loading" });
  const [swapStatus, setSwapStatus] = useState<NeutralStatus | null>(null);

  const asset = assets.find((a) => a.key === sel);
  const sourceChainNum = asset ? numericChainId(asset.chainId) : null;
  const sourceToken = useMemo(
    () => (asset && sourceChainNum ? sendAssetToProviderToken(asset, sourceChainNum, tokensByChain) : null),
    [asset, sourceChainNum, tokensByChain],
  );
  const targetTokens = targetChainId ? (tokensByChain.get(targetChainId) ?? []) : [];
  const targetToken = targetTokens.find((tk) => tokenKeyOf(tk) === targetTokenKey) ?? null;
  const targetChain = targetChainId
    ? supportedChains.find((c) => c.chainId === targetChainId) ?? null
    : null;
  const sourceItems = useMemo<SwapPickerItem[]>(
    () =>
      assets
        .flatMap((a) => {
          const chainId = numericChainId(a.chainId);
          if (!chainId) return [];
          const token = sendAssetToProviderToken(a, chainId, tokensByChain);
          return [{
            chainId,
            chainName: a.chainName,
            chainLogo: a.logo,
            chainSymbol: a.symbol,
            key: a.key,
            token,
            balance: `${fmtUnitsDisplay(a.wei, a.decimals)} ${a.symbol}`,
            providers: swapTokenProviders(token),
            sourceAssetKey: a.key,
          } satisfies SwapPickerItem];
        }),
    [assets, tokensByChain],
  );
  const targetItems = useMemo<SwapPickerItem[]>(() => {
    const out: SwapPickerItem[] = [];
    for (const chain of supportedChains) {
      for (const token of tokensByChain.get(chain.chainId) ?? []) {
        out.push({
          chainId: chain.chainId,
          chainName: chain.name,
          chainLogo: chain.logo,
          chainSymbol: chain.nativeSymbol,
          key: `${chain.chainId}:${tokenKeyOf(token)}`,
          token,
          providers: token.providers,
        });
      }
    }
    return out;
  }, [supportedChains, tokensByChain]);
  const supportedChainsByProvider = useMemo(() => {
    const map = new Map<ProviderId, Set<number>>();
    for (const p of PROVIDERS) map.set(p.id, new Set());
    for (const c of supportedChains) {
      for (const id of c.providers) map.get(id)?.add(c.chainId);
    }
    return map;
  }, [supportedChains]);
  const selectedQuote = selectedProvider
    ? (quoteSlots.find((s) => s.providerId === selectedProvider)?.quote ?? null)
    : null;
  const amountRaw = useMemo(() => {
    if (!sourceToken) return null;
    try {
      return parseUnits(amount.trim() || "0", sourceToken.decimals);
    } catch {
      return null;
    }
  }, [amount, sourceToken]);
  const insufficient =
    !!asset && !!amountRaw && amountRaw > 0n && amountRaw > BigInt(asset.wei);
  const approveKey =
    asset && selectedQuote?.approvalSpender && amountRaw
      ? `${asset.chainId}:${asset.address ?? NATIVE_TOKEN_ADDRESS}:${selectedQuote.approvalSpender}:${amountRaw.toString()}`.toLowerCase()
      : "";
  const needsApprove =
    !!asset &&
    !!selectedQuote?.approvalSpender &&
    !isNativeAddress(sourceToken?.address ?? NATIVE_TOKEN_ADDRESS) &&
    !approved.has(approveKey);
  const anyQuoteLoading = quoteSlots.some((s) => s.loading);

  useEffect(() => {
    let cancelled = false;
    setStage({ kind: "loading" });
    void loadSupportedSets()
      .then((sets) => {
        if (cancelled) return;
        setSupportedChains(sets.chains);
        setTokensByChain(sets.tokensByChain);
        setStage({ kind: "idle" });
      })
      .catch((e) => {
        if (!cancelled) setStage({ kind: "error", message: errText(e) });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (supportedChains.length === 0 || tokensByChain.size === 0) return;
    if (targetChainId && targetTokens.length > 0 && targetTokenKey) return;
    const preferred =
      supportedChains.find((c) => c.chainId !== sourceChainNum) ?? supportedChains[0];
    if (!preferred) return;
    const tokens = tokensByChain.get(preferred.chainId) ?? [];
    const native = tokens.find((tk) => isNativeAddress(tk.address)) ?? tokens[0];
    setTargetChainId(preferred.chainId);
    setTargetTokenKey(native ? tokenKeyOf(native) : "");
  }, [sourceChainNum, supportedChains, targetChainId, targetTokenKey, targetTokens.length, tokensByChain]);

  useEffect(() => {
    setUserPickedProvider(false);
  }, [sel, targetChainId, targetTokenKey]);

  useEffect(() => {
    if (!sourceToken || !targetToken || !sourceChainNum || !targetChainId || !amount.trim()) {
      setQuoteSlots(swapInitialSlots());
      setSelectedProvider(null);
      return;
    }
    if (!amountRaw || amountRaw <= 0n) {
      setQuoteSlots(swapInitialSlots());
      setSelectedProvider(null);
      return;
    }
    let cancelled = false;
    const timer = window.setTimeout(async () => {
      const params: QuoteParams = {
        fromChainId: sourceChainNum,
        toChainId: targetChainId,
        fromToken: sourceToken,
        toToken: targetToken,
        fromAddress: activeAddress,
        toAddress: activeAddress,
        fromAmount: amount.trim(),
        slippage,
      };
      setQuoteSlots(swapLoadingSlots());
      try {
        const slots = await fetchAllQuotes(params, supportedChainsByProvider);
        if (cancelled) return;
        setQuoteSlots(slots);
        if (!userPickedProvider) {
          setSelectedProvider(pickBestSlot(slots)?.providerId ?? null);
        }
      } catch (e) {
        if (!cancelled) setStage({ kind: "error", message: errText(e) });
      }
    }, 450);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [
    activeAddress,
    amount,
    amountRaw,
    slippage,
    sourceChainNum,
    sourceToken,
    supportedChainsByProvider,
    targetChainId,
    targetToken,
    userPickedProvider,
  ]);

  function setMax() {
    if (!asset) return;
    setAmount(formatUnits(asset.wei, asset.decimals, asset.decimals));
  }

  function pickAsset(item: SwapPickerItem) {
    if (pickerMode === "source") {
      if (item.sourceAssetKey) setSel(item.sourceAssetKey);
    } else {
      setTargetChainId(item.chainId);
      setTargetTokenKey(tokenKeyOf(item.token));
    }
    setPickerMode(null);
  }

  async function approve() {
    if (!asset || !selectedQuote?.approvalSpender || !sourceToken) return;
    if (!amountRaw || amountRaw <= 0n) {
      setStage({ kind: "error", message: t("wallet.invalidAmount") });
      return;
    }
    setStage({ kind: "approving" });
    const sendApprove = async (value: bigint) => {
      const hash = await walletSend(asset.chainId, {
        to: sourceToken.address,
        value: "0x0",
        data: encodeErc20Approve(selectedQuote.approvalSpender!, value),
        activity: {
          kind: "contract",
          counterparty: selectedQuote.approvalSpender,
          assetSymbol: sourceToken.symbol,
          tokenAddress: sourceToken.address,
          amount: toHexQuantity(value),
        },
      });
      await waitForTxSuccess(asset.chainId, hash, "Approve");
    };
    try {
      try {
        await sendApprove(amountRaw);
      } catch (e) {
        if (!isApproveResetRequiredError(e)) throw e;
        await sendApprove(0n);
        await sendApprove(amountRaw);
      }
      setApproved((prev) => new Set(prev).add(approveKey));
      setStage({ kind: "idle" });
    } catch (e) {
      setStage({ kind: "error", message: errText(e) });
    }
  }

  async function swap() {
    if (!asset || !sourceToken || !targetToken || !sourceChainNum || !targetChainId || !selectedQuote || !selectedProvider) return;
    if (!amountRaw || amountRaw <= 0n) return setStage({ kind: "error", message: t("wallet.invalidAmount") });
    if (insufficient) return setStage({ kind: "error", message: t("wallet.insufficient") });
    setStage({ kind: "swapping" });
    setSwapStatus(null);
    const params: QuoteParams = {
      fromChainId: sourceChainNum,
      toChainId: targetChainId,
      fromToken: sourceToken,
      toToken: targetToken,
      fromAddress: activeAddress,
      toAddress: activeAddress,
      fromAmount: amount.trim(),
      slippage,
    };
    try {
      const provider = getProvider(selectedProvider);
      const prepared = await provider.prepareSwap(params, selectedQuote);
      const fromChainId = numberToChainId(prepared.swapTx.chainId);
      const fromChainName =
        findChain(fromChainId)?.name ?? asset.chainName ?? fromChainId;
      const toChainId = numberToChainId(targetChainId);
      const toChainName =
        targetChain?.name ?? findChain(toChainId)?.name ?? toChainId;
      const hash = await walletSend(fromChainId, {
        to: prepared.swapTx.to,
        data: prepared.swapTx.data || "0x",
        value: normalizeTxValue(prepared.swapTx.value),
        activity: {
          kind: "swap",
          counterparty: prepared.swapTx.to,
          assetSymbol: `${sourceToken.symbol}->${targetToken.symbol}`,
          assetDecimals: sourceToken.decimals,
          amount: toHexQuantity(amountRaw),
          swap: {
            provider: providerName(selectedProvider),
            fromSymbol: sourceToken.symbol,
            fromAmount: toHexQuantity(amountRaw),
            fromDecimals: sourceToken.decimals,
            fromChainName,
            toSymbol: targetToken.symbol,
            toAmount: toHexQuantity(BigInt(selectedQuote.amountOutRaw)),
            toDecimals: targetToken.decimals,
            toChainName,
          },
        },
      });
      setStage({
        kind: "submitted",
        hash,
        providerId: selectedProvider,
        requestId: prepared.requestId,
        fromChainId,
        fromChainName,
        toChainId,
        toChainName,
      });
      void pollSwapStatus(params, hash, selectedProvider, prepared.requestId, setSwapStatus);
    } catch (e) {
      setStage({ kind: "error", message: errText(e) });
    }
  }

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div
        className={`modal swap-modal t-modal ${cls}`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="modal-head">
          <div>
            <div className="modal-title">{t("wallet.bridge")}</div>
            <div className="swap-provider-sub">XFlows · Relay</div>
          </div>
          <button className="icon-btn bare" onClick={close}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          {assets.length === 0 ? (
            <div className="add-note">{t("wallet.noSendable")}</div>
          ) : (
            <>
          <div className="swap-box">
            <div className="swap-side-label">{t("wallet.from")}</div>
            <div className="swap-input-row">
              <SwapAssetButton
                token={sourceToken}
                chainName={asset?.chainName}
                chainLogo={asset?.logo}
                balance={asset ? `${fmtUnitsDisplay(asset.wei, asset.decimals)} ${asset.symbol}` : undefined}
                providers={swapTokenProviders(sourceToken)}
                onClick={() => setPickerMode("source")}
                placeholder={t("wallet.selectToken")}
              />
              <input
                className="swap-amount-input"
                inputMode="decimal"
                placeholder="0.0"
                value={amount}
                onChange={(e) => setAmount(cleanDecimal(e.target.value))}
              />
            </div>
            {asset && (
              <div className="swap-side-meta">
                <span>
                  {t("wallet.available")}: {fmtUnitsDisplay(asset.wei, asset.decimals)} {asset.symbol}
                </span>
                <button className="swap-mini-btn" onClick={setMax}>{t("wallet.max")}</button>
              </div>
            )}
          </div>

          <div className="swap-flip-mark">
            <Icon name="swap" size={17} />
          </div>

          <div className="swap-box">
            <div className="swap-side-label">{t("wallet.to")}</div>
            <div className="swap-input-row">
              <SwapAssetButton
                token={targetToken}
                chainName={targetChain?.name}
                chainLogo={targetChain?.logo}
                providers={targetToken?.providers}
                onClick={() => setPickerMode("target")}
                placeholder={t("wallet.selectToken")}
              />
              <div className="swap-amount-readonly">
                {anyQuoteLoading && !selectedQuote
                  ? t("wallet.fetchingQuotes")
                  : selectedQuote
                    ? trimAmount(selectedQuote.amountOut, 8)
                    : "—"}
              </div>
            </div>
            {selectedQuote && targetToken && (
              <div className="swap-side-meta muted">
                {t("wallet.minReceived")}: {trimAmount(selectedQuote.amountOutMin, 8)} {targetToken.symbol}
              </div>
            )}
          </div>

          <QuoteChooser
            slots={quoteSlots}
            selectedProvider={selectedProvider}
            toSymbol={targetToken?.symbol ?? ""}
            onSelect={(id) => {
              setUserPickedProvider(true);
              setSelectedProvider(id);
            }}
          />

          <div className="swap-summary-card">
            <div className="swap-summary-row">
              <span>{t("wallet.slippage")}</span>
              <div className="swap-slippage">
                {[0.005, 0.01, 0.03].map((v) => (
                  <button
                    key={v}
                    className={`swap-mini-btn${slippage === v ? " on" : ""}`}
                    onClick={() => setSlippage(v)}
                  >
                    {(v * 100).toFixed(v < 0.01 ? 1 : 0)}%
                  </button>
                ))}
              </div>
            </div>
            {selectedQuote?.routeDescription && (
              <div className="swap-summary-row">
                <span>{t("wallet.route")}</span>
                <b>{selectedQuote.routeDescription}</b>
              </div>
            )}
            {selectedQuote?.priceImpact != null && (
              <div className="swap-summary-row">
                <span>{t("wallet.priceImpact")}</span>
                <b>{selectedQuote.priceImpact.toFixed(2)}%</b>
              </div>
            )}
            {selectedQuote && <SwapFeeBreakdown fees={selectedQuote.fees} t={t} />}
          </div>

          {stage.kind === "submitted" && (
            <SwapStatusView
              status={swapStatus}
              hash={stage.hash}
              provider={stage.providerId}
              fromChainId={stage.fromChainId}
              fromChainName={stage.fromChainName}
              toChainId={stage.toChainId}
              toChainName={stage.toChainName}
              t={t}
            />
          )}
          {stage.kind === "error" && (
            <div className="lock-err">
              <Icon name="alert" size={16} /> {stage.message}
            </div>
          )}

          <div className="swap-footer">
            <button className="btn btn-ghost swap-footer-btn" onClick={close}>
              {t("wallet.cancel")}
            </button>
            {needsApprove ? (
              <button className="btn btn-aurora swap-footer-btn primary" disabled={stage.kind === "approving"} onClick={() => void approve()}>
                {stage.kind === "approving" ? t("wallet.approving") : t("wallet.approveToken", { symbol: sourceToken?.symbol ?? "" })}
              </button>
            ) : (
              <button
                className="btn btn-aurora swap-footer-btn primary"
                disabled={!selectedQuote || anyQuoteLoading || insufficient || stage.kind === "swapping"}
                onClick={() => void swap()}
              >
                {stage.kind === "swapping"
                  ? t("wallet.submitting")
                  : selectedProvider
                    ? t("wallet.swapVia", { provider: providerName(selectedProvider) })
                    : t("wallet.bridge")}
              </button>
            )}
          </div>
            </>
          )}
        </div>
        {pickerMode && (
          <SwapAssetPicker
            title={pickerMode === "source" ? t("wallet.selectFromAsset") : t("wallet.selectToAsset")}
            items={pickerMode === "source" ? sourceItems : targetItems}
            selectedKey={
              pickerMode === "source"
                ? sel
                : targetChainId && targetToken
                  ? `${targetChainId}:${tokenKeyOf(targetToken)}`
                  : ""
            }
            t={t}
            onPick={pickAsset}
            onClose={() => setPickerMode(null)}
          />
        )}
      </div>
    </div>
  );
}

function SendModal({
  assets,
  initialAssetKey,
  onClose,
}: {
  assets: SendAsset[];
  initialAssetKey?: string;
  onClose: () => void;
}) {
  const { t } = useT();
  const { cls, close } = useModalExit(onClose);
  const accounts = useAccounts();
  const [sel, setSel] = useState<string>(
    initialAssetKey && assets.some((a) => a.key === initialAssetKey)
      ? initialAssetKey
      : (assets[0]?.key ?? ""),
  );
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<RequestPhase>("preparing");
  const [error, setError] = useState<string | null>(null);

  // Follow the backend's own progress instead of claiming "confirm in window"
  // from the first click: the window only exists once the phase says so.
  useEffect(() => {
    if (!busy) return;
    return onRequestPhase(setPhase);
  }, [busy]);

  const asset = assets.find((a) => a.key === sel);
  const recipientQuery = recipient.trim().toLowerCase();
  const recipientMatches = useMemo(() => {
    if (!recipientQuery || isAddress(recipient)) return [];
    return accounts
      .filter((a) =>
        [a.label, a.address, shortAddress(a.address, 10, 6), a.kind]
          .join(" ")
          .toLowerCase()
          .includes(recipientQuery),
      )
      .slice(0, 5);
  }, [accounts, recipient, recipientQuery]);
  const resolvedRecipient = resolveRecipient(recipient);

  function setMax() {
    if (asset)
      setAmount(formatUnits(asset.wei, asset.decimals, asset.decimals));
  }

  async function submit() {
    if (!asset) return;
    const to = resolvedRecipient;
    if (!to)
      return setError(
        recipientMatches.length > 0
          ? t("wallet.chooseRecipient")
          : t("wallet.invalidRecipient"),
      );
    let amountWei: bigint;
    try {
      amountWei = parseUnits(amount, asset.decimals);
    } catch {
      return setError(t("wallet.invalidAmount"));
    }
    if (amountWei <= 0n) return setError(t("wallet.invalidAmount"));
    if (amountWei > BigInt(asset.wei))
      return setError(t("wallet.insufficient"));

    const tx =
      asset.kind === "native"
        ? {
            to,
            value: toHexQuantity(amountWei),
            activity: {
              kind: "send" as const,
              counterparty: to,
              assetSymbol: asset.symbol,
              assetDecimals: asset.decimals,
              amount: toHexQuantity(amountWei),
            },
          }
        : {
            to: asset.address as string,
            value: "0x0",
            data: encodeErc20Transfer(to, amountWei),
            activity: {
              kind: "token_send" as const,
              counterparty: to,
              assetSymbol: asset.symbol,
              assetDecimals: asset.decimals,
              amount: toHexQuantity(amountWei),
              tokenAddress: asset.address,
            },
          };

    setBusy(true);
    setPhase("preparing");
    setError(null);
    try {
      await walletSend(asset.chainId, tx);
      close();
    } catch (e) {
      setError(errText(e));
      setBusy(false);
    }
  }

  return (
    <div className={`scrim t-scrim ${cls}`} onClick={close}>
      <div className={`modal t-modal ${cls}`} onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">{t("wallet.send")}</div>
          <button className="icon-btn bare" onClick={close}>
            <Icon name="close" size={18} />
          </button>
        </div>
        <div className="modal-body">
          {assets.length === 0 ? (
            <div className="add-note">{t("wallet.noSendable")}</div>
          ) : (
            <div className="add-form">
              <div className="field">
                <label className="field-label">{t("wallet.sendAsset")}</label>
                <AssetSelect
                  assets={assets}
                  selected={asset}
                  onChange={(key) => {
                    setSel(key);
                    setError(null);
                  }}
                />
              </div>
              <div className="field">
                <label className="field-label">{t("wallet.recipient")}</label>
                <input
                  className="input mono"
                  value={recipient}
                  placeholder={t("wallet.recipientPlaceholder")}
                  onChange={(e) => {
                    setRecipient(e.target.value);
                    setError(null);
                  }}
                />
                {recipientMatches.length > 0 && (
                  <div className="recipient-options">
                    {recipientMatches.map((a) => (
                      <button
                        key={a.address}
                        className="recipient-option"
                        onClick={() => {
                          setRecipient(a.address);
                          setError(null);
                        }}
                      >
                        <Avatar address={a.address} size={24} />
                        <span className="recipient-option-meta">
                          <span>{a.label}</span>
                          <span>{shortAddress(a.address, 10, 6)}</span>
                        </span>
                        <KindBadge
                          kind={a.kind === "watch" ? "watch" : a.kind}
                          t={t}
                        />
                      </button>
                    ))}
                  </div>
                )}
              </div>
              <div className="field">
                <label className="field-label">
                  {t("wallet.amount")}
                  {asset && (
                    <span className="field-aux">
                      {t("wallet.available")}:{" "}
                      {fmtUnitsDisplay(asset.wei, asset.decimals)} {asset.symbol}
                    </span>
                  )}
                </label>
                <div className="scan-row">
                  <input
                    className="input mono"
                    value={amount}
                    inputMode="decimal"
                    placeholder="0.0"
                    onChange={(e) => {
                      setAmount(e.target.value);
                      setError(null);
                    }}
                    onKeyDown={(e) => e.key === "Enter" && void submit()}
                  />
                  <button className="btn btn-ghost btn-sm" onClick={setMax}>
                    {t("wallet.max")}
                  </button>
                </div>
              </div>
              {error && (
                <div className="lock-err">
                  <Icon name="alert" size={16} /> {error}
                </div>
              )}
              <div className="add-note send-note">
                <Icon name="info" size={15} /> {t("wallet.sendApprovalHint")}
              </div>
              <div className="add-acts">
                <button className="btn btn-ghost btn-sm" onClick={close}>
                  {t("wallet.cancel")}
                </button>
                <button
                  className="btn btn-aurora btn-sm"
                  disabled={busy || !asset || !resolvedRecipient || !amount}
                  onClick={() => void submit()}
                >
                  {busy ? t(`wallet.phase.${phase}`) : t("wallet.send")}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
