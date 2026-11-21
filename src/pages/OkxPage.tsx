import { FormEvent, useEffect, useMemo, useState } from "react";
import "./OkxPage.css";
import { Coin, EmptyState, InlineError, TableSkeleton, formatCurrencyAmount, formatDate, formatMoney } from "./OkxDisplay";
import { FlexibleLoanSection, SavingsTable, TradingBalanceTable } from "./OkxFinance";
import { saveOkxDcdCsv } from "../lib/okxCsv";
import { askConfirm } from "../lib/confirm";
import { Icon } from "../lib/icons";
import { useT } from "../lib/i18n";
import {
  calculateOkxDcdRealizedApr,
  deleteOkxCredentials,
  createSingleFlight,
  estimateOkxDcdOrderYieldUsd,
  getOkxAssets,
  getOkxConnectionStatus,
  getOkxDcdOrders,
  getOkxDcdIndexInstrumentId,
  getOkxDcdIndexPrices,
  getOkxDcdRealizedYield,
  isCurrentDcdOrder,
  isUsdStablecoin,
  mergeOkxPortfolioAssets,
  saveOkxCredentials,
  sumOkxDcdYieldByCurrency,
  sumOkxDcdYieldUsd,
  type OkxAssets,
  type OkxConnectionStatus,
  type OkxCredentialsInput,
  type OkxDcdOrder,
  type OkxIndexPrice,
  type OkxPortfolioAsset,
  type OkxRegion,
} from "../lib/okxAccount";
import { getOkxFlexibleLoanRates, getOkxFlexibleLoans, getOkxSavings, type OkxFlexibleLoans, type OkxLoanRates, type OkxSavings } from "../lib/okxFinance";
import { openExternalUrl } from "../lib/platform";

const API_KEY_URL = "https://www.okx.com/account/my-api";

const REGIONS: { value: OkxRegion; label: string }[] = [
  { value: "global", label: "Global · www.okx.com" },
  { value: "us", label: "US / Australia · us.okx.com" },
  { value: "eu", label: "Europe · eea.okx.com" },
  { value: "tr", label: "Türkiye · tr.okx.com" },
];

const STATE_KEYS: Record<OkxDcdOrder["state"], string> = {
  initial: "okx.state.initial",
  live: "okx.state.live",
  pending_settle: "okx.state.pendingSettle",
  settled: "okx.state.settled",
  pending_redeem: "okx.state.pendingRedeem",
  redeemed: "okx.state.redeemed",
  rejected: "okx.state.rejected",
};

function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  if (typeof error === "string") return error;
  return String(error);
}

function signedAmount(value: string, formatted: string): string {
  return Number(value) > 0 ? `+${formatted}` : formatted;
}

function formatEstimatedUsd(value: string): string {
  const number = Number(value);
  if (Number.isFinite(number) && number < 0) return `(-$${formatMoney((-number).toString())})`;
  return `($${formatMoney(value)})`;
}

function formatSignedUsd(value: string): string {
  const number = Number(value);
  if (!Number.isFinite(number)) throw new Error(`Invalid USD amount: ${value}`);
  if (number < 0) return `-$${formatMoney((-number).toString())}`;
  return `${number > 0 ? "+" : ""}$${formatMoney(value)}`;
}

function formatYield(value: string): string {
  const number = Number(value);
  if (!Number.isFinite(number)) return value;
  return `${(number * 100).toFixed(2)}%`;
}

export default function OkxPage() {
  const [status, setStatus] = useState<OkxConnectionStatus | null>(null);
  const [statusError, setStatusError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    getOkxConnectionStatus().then((next) => {
      if (active) setStatus(next);
    }, (error) => {
      if (active) setStatusError(errorMessage(error));
    });
    return () => { active = false; };
  }, []);

  if (statusError !== null) return <PageError message={statusError} />;
  if (status === null) return <div className="okx-page okx-loading"><span /><span /><span /></div>;
  if (!status.configured) return <OkxSetup onConnected={setStatus} />;

  return <ConnectedOkxPage status={status} onDisconnected={() => {
    setStatus({ configured: false, apiKeyHint: null, region: null });
  }} />;
}

function ConnectedOkxPage({ status, onDisconnected }: {
  status: Extract<OkxConnectionStatus, { configured: true }>;
  onDisconnected: () => void;
}) {
  const { t } = useT();
  const [assets, setAssets] = useState<OkxAssets | null>(null);
  const [assetsError, setAssetsError] = useState<string | null>(null);
  const [savings, setSavings] = useState<OkxSavings | null>(null);
  const [savingsError, setSavingsError] = useState<string | null>(null);
  const [loans, setLoans] = useState<OkxFlexibleLoans | null>(null);
  const [loansError, setLoansError] = useState<string | null>(null);
  const [loanRates, setLoanRates] = useState<OkxLoanRates | null>(null);
  const [loanRatesError, setLoanRatesError] = useState<string | null>(null);
  const [orders, setOrders] = useState<OkxDcdOrder[] | null>(null);
  const [ordersError, setOrdersError] = useState<string | null>(null);
  const [indexPrices, setIndexPrices] = useState<OkxIndexPrice[] | null>(null);
  const [priceError, setPriceError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [showAllOrders, setShowAllOrders] = useState(true);
  const [showConnection, setShowConnection] = useState(false);
  const [disconnectError, setDisconnectError] = useState<string | null>(null);

  const refreshData = useMemo(() => createSingleFlight(() => {
    setRefreshing(true);
    setAssetsError(null);
    setSavingsError(null);
    setLoansError(null);
    setLoanRatesError(null);
    setOrdersError(null);
    setPriceError(null);
    setIndexPrices(null);
    const ordersRequest = getOkxDcdOrders().then((nextOrders) => {
      setOrders(nextOrders);
      return nextOrders;
    });
    const pricesRequest = ordersRequest.then((nextOrders) => {
      const instrumentIds = Array.from(new Set(nextOrders.map((order) => (
        getOkxDcdIndexInstrumentId(order.productId)
      ))));
      return getOkxDcdIndexPrices(instrumentIds);
    });
    const loanRequest = getOkxFlexibleLoans().then((nextLoans) => {
      setLoans(nextLoans);
      setLoanRates(null);
      return getOkxFlexibleLoanRates(nextLoans.orders.map((loan) => loan.orderId)).then(
        setLoanRates, (error) => setLoanRatesError(errorMessage(error)),
      );
    }, (error) => setLoansError(errorMessage(error)));
    return Promise.all([
      getOkxAssets().then(setAssets, (error) => setAssetsError(errorMessage(error))),
      getOkxSavings().then(setSavings, (error) => setSavingsError(errorMessage(error))),
      loanRequest,
      ordersRequest.catch((error) => setOrdersError(errorMessage(error))),
      pricesRequest.then(setIndexPrices, (error) => setPriceError(errorMessage(error))),
    ]).then(() => {
      setRefreshing(false);
    });
  }), []);

  useEffect(() => {
    void refreshData();
  }, [refreshData]);

  const visibleOrders = useMemo(() => {
    if (orders === null) return null;
    return showAllOrders ? orders : orders.filter(isCurrentDcdOrder);
  }, [orders, showAllOrders]);

  const disconnect = () => {
    setDisconnectError(null);
    void askConfirm({
      title: t("okx.disconnectTitle"),
      message: t("okx.disconnectHint"),
      confirmLabel: t("okx.disconnect"),
      cancelLabel: t("common.cancel"),
      danger: true,
    }).then((approved) => {
      if (!approved) return;
      return deleteOkxCredentials().then(onDisconnected);
    }).catch((error) => {
      setDisconnectError(errorMessage(error));
    });
  };

  return (
    <div className="okx-page">
      <header className="okx-header">
        <div>
          <div className="okx-eyebrow"><OkxMark size={18} /> OKX</div>
          <h1>{t("okx.title")}</h1>
          <p>{t("okx.subtitle")}</p>
        </div>
        <div className="okx-header-actions">
          <span className="okx-connected"><i />{t("okx.connected")} · {status.apiKeyHint}</span>
          <button className="okx-icon-button" title={t("okx.connection")} onClick={() => setShowConnection((value) => !value)}>
            <Icon name="settings" size={18} />
          </button>
          <button className="okx-refresh" disabled={refreshing} onClick={() => void refreshData()}>
            <Icon name="refresh" size={16} />
            {refreshing ? t("okx.refreshing") : t("wallet.refresh")}
          </button>
        </div>
      </header>

      {showConnection && (
        <section className="okx-connection-bar">
          <div>
            <strong>{t("okx.connection")}</strong>
            <span>{status.apiKeyHint} · {regionLabel(status.region)}</span>
            {disconnectError !== null && <InlineError message={disconnectError} />}
          </div>
          <button className="okx-danger-link" onClick={disconnect}>{t("okx.disconnect")}</button>
        </section>
      )}

      <section className="okx-balance-hero">
        <div className="okx-pixel-field" aria-hidden="true">
          {Array.from({ length: 9 }, (_, index) => <i key={index} />)}
        </div>
        <div className="okx-hero-total">
          <span>{t("okx.totalEquity")}</span>
          <strong className="tnum">{assets === null ? "—" : formatMoney(assets.totalEquityUsd)} <em>USDT</em></strong>
          <small>{assets === null ? t("okx.loadingAssets") : t("okx.updatedAt", { time: formatDate(assets.updatedAt) })}</small>
        </div>
        <div className="okx-account-overview">
          <div className="okx-account-overview-head">
            <span>{t("okx.accountDistribution")}</span>
            <div className="okx-hero-note"><Icon name="shieldCheck" size={15} />{t("okx.readOnly")}</div>
          </div>
          <div className="okx-account-values">
            {(["funding", "trading", "earn"] as const).map((account) => (
              <div key={account}>
                <span><i className={account} />{t(`okx.account.${account}`)}</span>
                <strong className="tnum">{assets === null ? "—" : formatMoney(assets.accountValues[account])}</strong>
                <small>USDT</small>
              </div>
            ))}
          </div>
        </div>
      </section>

      <FlexibleLoanSection loans={loans} loanRates={loanRates} rateError={loanRatesError} error={loansError} />

      <AccountBalances assets={assets} assetsError={assetsError} savings={savings} savingsError={savingsError}
        orders={orders} ordersError={ordersError} />

      <section className="okx-section okx-orders-section">
        <div className="okx-section-head">
          <div>
            <h2>{t("okx.dualInvestment")}</h2>
            <p>{t("okx.dualInvestmentHint")}</p>
          </div>
          <OrderHeadActions
            allOrders={ordersError === null ? orders : null}
            indexPrices={indexPrices}
            showAllOrders={showAllOrders}
            onShowAllOrders={setShowAllOrders}
          />
        </div>
        {ordersError !== null
          ? <DcdError message={ordersError} />
          : <OrderList orders={visibleOrders} indexPrices={indexPrices} priceError={priceError} />}
      </section>
    </div>
  );
}

function OkxSetup({ onConnected }: { onConnected: (status: OkxConnectionStatus) => void }) {
  const { t } = useT();
  const [form, setForm] = useState<OkxCredentialsInput>({
    apiKey: "",
    secretKey: "",
    passphrase: "",
    region: "global",
  });
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError(null);
    void saveOkxCredentials({
      apiKey: form.apiKey.trim(),
      secretKey: form.secretKey.trim(),
      passphrase: form.passphrase,
      region: form.region,
    }).then(onConnected).catch((reason) => {
      setError(errorMessage(reason));
      setSaving(false);
    });
  };

  return (
    <div className="okx-page okx-setup-page">
      <div className="okx-setup-intro">
        <div className="okx-setup-brand"><OkxMark size={44} /></div>
        <span className="okx-kicker">OKX · READ ONLY</span>
        <h1>{t("okx.setupTitle")}</h1>
        <p>{t("okx.setupSubtitle")}</p>
        <ol className="okx-steps">
          <li><b>01</b><span><strong>{t("okx.stepCreate")}</strong><small>{t("okx.stepCreateHint")}</small></span></li>
          <li><b>02</b><span><strong>{t("okx.stepPermission")}</strong><small>{t("okx.stepPermissionHint")}</small></span></li>
          <li><b>03</b><span><strong>{t("okx.stepConnect")}</strong><small>{t("okx.stepConnectHint")}</small></span></li>
        </ol>
        <button className="okx-open-api" onClick={() => void openExternalUrl(API_KEY_URL)}>
          {t("okx.openApiPage")} <Icon name="external" size={16} />
        </button>
      </div>

      <form className="okx-setup-form" onSubmit={submit}>
        <div className="okx-form-heading">
          <span><Icon name="key" size={18} /></span>
          <div><h2>{t("okx.connectTitle")}</h2><p>{t("okx.connectHint")}</p></div>
        </div>
        <label>
          <span>{t("okx.region")}</span>
          <select value={form.region} onChange={(event) => setForm({ ...form, region: event.target.value as OkxRegion })}>
            {REGIONS.map((region) => <option key={region.value} value={region.value}>{region.label}</option>)}
          </select>
        </label>
        <label>
          <span>API Key</span>
          <input autoComplete="off" value={form.apiKey} onChange={(event) => setForm({ ...form, apiKey: event.target.value })} required />
        </label>
        <label>
          <span>Secret Key</span>
          <input type="password" autoComplete="new-password" value={form.secretKey} onChange={(event) => setForm({ ...form, secretKey: event.target.value })} required />
        </label>
        <label>
          <span>Passphrase</span>
          <input type="password" autoComplete="new-password" value={form.passphrase} onChange={(event) => setForm({ ...form, passphrase: event.target.value })} required />
        </label>
        <div className="okx-storage-note"><Icon name="lock" size={16} /><span>{t("okx.storageNote")}</span></div>
        {error !== null && <InlineError message={error} />}
        <button className="okx-connect-button" disabled={saving} type="submit">
          {saving ? t("okx.verifying") : t("okx.verifyConnect")}
          {!saving && <Icon name="chevronR" size={16} />}
        </button>
      </form>
    </div>
  );
}

const BALANCE_VIEWS = ["combined", "trading", "funding", "earn"] as const;

function AccountBalances({ assets, assetsError, savings, savingsError, orders, ordersError }: {
  assets: OkxAssets | null;
  assetsError: string | null;
  savings: OkxSavings | null;
  savingsError: string | null;
  orders: OkxDcdOrder[] | null;
  ordersError: string | null;
}) {
  const { t } = useT();
  const [view, setView] = useState<(typeof BALANCE_VIEWS)[number]>("combined");
  const combined = useMemo(() => assets === null ? null : mergeOkxPortfolioAssets(
    assets,
    orders === null || ordersError !== null ? [] : orders,
    savings === null || savingsError !== null ? [] : savings.balances,
  ), [assets, orders, ordersError, savings, savingsError]);
  const funding = useMemo(() => assets === null ? null : mergeOkxPortfolioAssets({
    assets: assets.assets.filter((row) => row.account === "funding"),
  }, []), [assets]);
  const dualInvestment = useMemo(() => orders === null ? null : mergeOkxPortfolioAssets({ assets: [] }, orders), [orders]);

  return (
    <section className="okx-section">
      <div className="okx-section-head">
        <div>
          <h2>{t("okx.assets")}</h2>
          <p>{t(`okx.balanceHint.${view}`)}</p>
        </div>
        <div className="okx-segmented okx-account-switcher" role="group" aria-label={t("okx.account")}>
          {BALANCE_VIEWS.map((item) => (
            <button key={item} type="button" className={item === view ? "on" : ""} aria-pressed={item === view}
              onClick={() => setView(item)}>{t(`okx.account.${item}`)}</button>
          ))}
        </div>
      </div>
      {view === "earn" ? (
        <>
          <div className="okx-balance-subhead"><h3>{t("okx.simpleEarn")}</h3><p>{t("okx.simpleEarnHint")}</p></div>
          <SavingsTable savings={savings} error={savingsError} />
          <div className="okx-balance-subhead"><h3>{t("okx.dualInvestmentBalance")}</h3></div>
          {ordersError !== null ? <DcdError message={ordersError} /> : <AssetTable assets={dualInvestment} />}
        </>
      ) : assetsError !== null ? <InlineError message={assetsError} />
        : view === "trading" ? <TradingBalanceTable balances={assets === null ? null : assets.tradingBalances} />
        : view === "funding" ? <AssetTable assets={funding} />
        : (
          <>
            {savingsError !== null || ordersError !== null ? <InlineError message={t("okx.partialBalances")} />
              : assets !== null && (savings === null || orders === null) && (
                <p className="okx-balances-pending" role="status">{t("okx.loadingEarnBalances")}</p>
              )}
            <AssetTable assets={combined} />
          </>
        )}
    </section>
  );
}

export function AssetTable({ assets }: { assets: OkxPortfolioAsset[] | null }) {
  const { t } = useT();
  if (assets === null) return <TableSkeleton rows={3} />;
  if (assets.length === 0) return <EmptyState title={t("okx.noAssets")} />;
  return (
    <div className="okx-table-wrap">
      <table className="okx-table">
        <thead><tr><th>{t("okx.asset")}</th><th>{t("okx.account")}</th><th>{t("okx.available")}</th><th>{t("okx.frozen")}</th><th>{t("okx.balance")}</th></tr></thead>
        <tbody>{assets.map((asset) => (
          <tr key={asset.currency}>
            <td><Coin currency={asset.currency} /><strong>{asset.currency}</strong></td>
            <td><div className="okx-account-tags">{asset.accounts.map((account) => (
              <span key={account} className={`okx-account-tag ${account}`}>{t(`okx.account.${account}`)}</span>
            ))}</div></td>
            <td className="tnum">{asset.available === null ? "—" : formatCurrencyAmount(asset.available, asset.currency)}</td>
            <td className="tnum">{asset.frozen === null ? "—" : formatCurrencyAmount(asset.frozen, asset.currency)}</td>
            <td className="tnum"><strong>{formatCurrencyAmount(asset.balance, asset.currency)}</strong>{asset.usdValue !== null && <small>${formatMoney(asset.usdValue)}</small>}</td>
          </tr>
        ))}</tbody>
      </table>
    </div>
  );
}

export function OrderYieldSummary({
  orders,
  indexPrices,
}: {
  orders: OkxDcdOrder[];
  indexPrices: OkxIndexPrice[] | null;
}) {
  const { t } = useT();
  const totals = sumOkxDcdYieldByCurrency(orders, indexPrices);
  const totalUsd = sumOkxDcdYieldUsd(orders, indexPrices);
  const averageApr = calculateOkxDcdRealizedApr(orders, indexPrices);
  return (
    <div className="okx-order-yield-summary">
      <span className="okx-order-yield-summary-icon"><Icon name="activity" size={16} /></span>
      <div className="okx-order-yield-summary-usd" title={t("okx.estimatedUsd")}>
        <span className="okx-order-yield-summary-label">{t("okx.totalYield")}</span>
        {totalUsd === null
          ? <strong className="okx-order-yield-summary-total okx-order-empty">—</strong>
          : (
            <strong className={`okx-order-yield-summary-total tnum${Number(totalUsd) < 0 ? " down" : ""}`}>
              {formatSignedUsd(totalUsd)}
            </strong>
          )}
      </div>
      {totals.length > 0 && (
        <>
          <span className="okx-order-yield-summary-divider" aria-hidden="true" />
          <div className="okx-order-yield-summary-breakdown">
            <span className="okx-order-yield-summary-label">{t("okx.yieldBreakdown")}</span>
            <div className="okx-order-yield-summary-values">
              {totals.map((total) => (
                <strong className="tnum" key={total.currency}>
                  {signedAmount(total.amount, formatCurrencyAmount(total.amount, total.currency))} {total.currency}
                  {!isUsdStablecoin(total.currency) && total.usdValue !== null && (
                    <small title={t("okx.estimatedUsd")}>{formatEstimatedUsd(total.usdValue)}</small>
                  )}
                </strong>
              ))}
            </div>
          </div>
        </>
      )}
      <span className="okx-order-yield-summary-divider" aria-hidden="true" />
      <div className="okx-order-yield-summary-average" title={t("okx.averageAprHint")}>
        <span className="okx-order-yield-summary-label">{t("okx.averageApr")}</span>
        <strong className="tnum">{averageApr === null ? "—" : formatYield(averageApr)}</strong>
      </div>
    </div>
  );
}

export function OrderHeadActions({
  allOrders,
  indexPrices,
  showAllOrders,
  onShowAllOrders,
}: {
  allOrders: OkxDcdOrder[] | null;
  indexPrices: OkxIndexPrice[] | null;
  showAllOrders: boolean;
  onShowAllOrders: (showAll: boolean) => void;
}) {
  const { t, lang } = useT();
  const [exporting, setExporting] = useState(false);
  const [exportMessage, setExportMessage] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  async function exportCsv() {
    if (allOrders === null || allOrders.length === 0 || exporting) return;
    setExporting(true);
    setExportMessage(null);
    setExportError(null);
    try {
      const path = await saveOkxDcdCsv(allOrders, lang === "zh");
      setExportMessage(`${t("okx.csvSaved")} ${path}${allOrders.length >= 100 ? ` · ${t("okx.csvLimit")}` : ""}`);
    } catch (error) {
      setExportError(errorMessage(error));
    } finally {
      setExporting(false);
    }
  }
  return (
    <div className="okx-order-head-actions">
      {allOrders !== null && <OrderYieldSummary orders={allOrders} indexPrices={indexPrices} />}
      <div className="okx-segmented">
        <button className={!showAllOrders ? "on" : ""} onClick={() => onShowAllOrders(false)}>{t("okx.current")}</button>
        <button className={showAllOrders ? "on" : ""} onClick={() => onShowAllOrders(true)}>{t("okx.all")}</button>
      </div>
      <button className="okx-csv-button" onClick={() => void exportCsv()}
        disabled={exporting || allOrders === null || allOrders.length === 0}
        title={t("okx.csvHint")}>
        <Icon name="download" size={16} />
        {t(exporting ? "okx.csvSaving" : "okx.csvDownload")}
      </button>
      {exportMessage !== null && <p className="okx-csv-message" role="status">{exportMessage}</p>}
      {exportError !== null && <p className="okx-csv-message" role="alert">{exportError}</p>}
    </div>
  );
}

export function OrderList({
  orders,
  indexPrices,
  priceError,
}: {
  orders: OkxDcdOrder[] | null;
  indexPrices: OkxIndexPrice[] | null;
  priceError: string | null;
}) {
  const { t } = useT();
  if (orders === null) return <TableSkeleton rows={2} />;
  if (orders.length === 0) return <EmptyState title={t("okx.noOrders")} hint={t("okx.noOrdersHint")} />;
  return (
    <div className="okx-order-table-wrap">
      <table className="okx-order-table">
        <thead>
          <tr>
            <th>{t("okx.product")}</th>
            <th>{t("okx.annualizedYield")}</th>
            <th>{t("okx.principal")}</th>
            <th>{t("okx.strike")}</th>
            <th>{t("okx.yield")}</th>
            <th>{t("okx.settlement")}</th>
            <th>{t("okx.timeline")}</th>
          </tr>
        </thead>
        <tbody>{orders.map((order) => {
          const [baseCurrency, quoteCurrency] = order.productId.split("-");
          if (baseCurrency === undefined || quoteCurrency === undefined) {
            throw new Error(`OKX Dual Investment product ${order.productId} has no currency pair`);
          }
          const realizedYield = getOkxDcdRealizedYield(order);
          const yieldUsdValue = estimateOkxDcdOrderYieldUsd(order, indexPrices);
          const indexInstrumentId = getOkxDcdIndexInstrumentId(order.productId);
          const indexPrice = indexPrices?.find((price) => price.instrumentId === indexInstrumentId);
          const eventTime = order.state === "redeemed" || order.state === "rejected"
            ? order.updatedAt
            : order.expiresAt;
          return (
            <tr key={order.orderId}>
              <td>
                <div className="okx-order-product">
                  <Coin currency={order.principalCurrency} />
                  <div>
                    <div className="okx-order-product-title">
                      <span className={`okx-option ${order.optionType}`}>{t(order.optionType === "call" ? "okx.sellHigh" : "okx.buyLow")}</span>
                      <strong>{baseCurrency} / {quoteCurrency}</strong>
                    </div>
                    <small className="okx-order-product-id">{order.productId}</small>
                    <small>{t("okx.orderId")} #{order.orderId}</small>
                  </div>
                </div>
              </td>
              <td><strong className="okx-order-apr tnum">{formatYield(order.annualizedYield)}</strong></td>
              <td><strong className="tnum">{formatCurrencyAmount(order.principal, order.principalCurrency)} {order.principalCurrency}</strong></td>
              <td>
                <div className="okx-order-prices">
                  <span>{t("okx.strike")}</span>
                  <strong className="tnum">{formatCurrencyAmount(order.strike, quoteCurrency)} {quoteCurrency}</strong>
                  <span title={t("okx.indexPriceHint")}>{t("okx.indexPrice")}</span>
                  {priceError === null
                    ? <strong className="tnum">{indexPrice === undefined
                      ? "—"
                      : `${formatCurrencyAmount(indexPrice.price, quoteCurrency)} ${quoteCurrency}`}</strong>
                    : <strong className="okx-order-price-error" title={priceError}>!</strong>}
                </div>
              </td>
              <td>
                <div className="okx-order-yield-cell">
                  {realizedYield !== null && (
                    <div className="okx-order-return">
                      <strong className="tnum">{signedAmount(realizedYield.amount, formatCurrencyAmount(realizedYield.amount, realizedYield.currency))} {realizedYield.currency}</strong>
                      {!isUsdStablecoin(realizedYield.currency) && yieldUsdValue !== null && (
                        <small className="tnum" title={t("okx.estimatedUsd")}>{formatEstimatedUsd(yieldUsdValue)}</small>
                      )}
                    </div>
                  )}
                  <span className={`okx-state ${order.state}`}>{t(STATE_KEYS[order.state])}</span>
                </div>
              </td>
              <td>
                <div className="okx-order-settlement">
                  <span>{t("okx.settledAmount")}</span>
                  <strong className="tnum">{order.settledAmount === null || order.settledCurrency === null
                    ? "—"
                    : `${formatCurrencyAmount(order.settledAmount, order.settledCurrency)} ${order.settledCurrency}`}</strong>
                  <span>{t("okx.settlementPrice")}</span>
                  <strong className="tnum">{order.settlementPrice === null
                    ? "—"
                    : `${formatCurrencyAmount(order.settlementPrice, quoteCurrency)} ${quoteCurrency}`}</strong>
                </div>
              </td>
              <td>
                <div className="okx-order-timeline">
                  <span>{t("okx.subscribedAt")}</span>
                  <time dateTime={new Date(order.createdAt).toISOString()}>{formatDate(order.createdAt)}</time>
                  <span>{t("okx.expiry")}</span>
                  <time dateTime={new Date(eventTime).toISOString()}>{formatDate(eventTime)}</time>
                </div>
              </td>
            </tr>
          );
        })}</tbody>
      </table>
    </div>
  );
}

function OkxMark({ size }: { size: number }) {
  return <span className="okx-mark" style={{ width: size, height: size }}><Icon name="okx" size={size} sw={0} fill="currentColor" /></span>;
}

function DcdError({ message }: { message: string }) {
  const { t } = useT();
  const accessDisabled = message.includes("50038") || message.includes("50030");
  return <div className="okx-dcd-error"><span><Icon name="info" size={20} /></span><div><strong>{accessDisabled ? t("okx.dcdAccessTitle") : t("okx.dcdErrorTitle")}</strong><p>{accessDisabled ? t("okx.dcdAccessHint") : message}</p>{accessDisabled && <code>{message}</code>}</div></div>;
}

function PageError({ message }: { message: string }) {
  return <div className="okx-page"><div className="okx-page-error"><OkxMark size={32} /><h2>OKX</h2><p>{message}</p></div></div>;
}

function regionLabel(region: OkxRegion): string {
  const match = REGIONS.find((item) => item.value === region);
  if (match === undefined) throw new Error(`Unsupported OKX region: ${region}`);
  return match.label;
}
