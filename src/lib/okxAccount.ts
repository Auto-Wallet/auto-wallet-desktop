import { array, okxInvoke, optionalString, parseEnvelope, record, string, timestamp } from "./okxResponse";
import type { OkxSaving } from "./okxFinance";

export type OkxRegion = "global" | "us" | "eu" | "tr";

export type OkxCredentialsInput = {
  apiKey: string;
  secretKey: string;
  passphrase: string;
  region: OkxRegion;
};

export type OkxConnectionStatus =
  | { configured: false; apiKeyHint: null; region: null }
  | { configured: true; apiKeyHint: string; region: OkxRegion };

export type OkxAsset = {
  account: "trading" | "funding";
  currency: string;
  balance: string;
  available: string;
  frozen: string;
  usdValue: string | null;
};

export type OkxPortfolioAsset = {
  accounts: ("trading" | "funding" | "earn")[];
  currency: string;
  balance: string;
  available: string | null;
  frozen: string | null;
  usdValue: string | null;
};

export type OkxTradingBalance = {
  currency: string;
  spotBalance: string | null;
  cashBalance: string | null;
  available: string | null;
  frozen: string | null;
  liability: string | null;
  interest: string | null;
};

export type OkxAssets = {
  totalEquityUsd: string;
  updatedAt: number;
  accountValues: {
    funding: string;
    trading: string;
    earn: string;
  };
  assets: OkxAsset[];
  tradingBalances: OkxTradingBalance[];
};

export type OkxDcdOrderState =
  | "initial"
  | "live"
  | "pending_settle"
  | "settled"
  | "pending_redeem"
  | "redeemed"
  | "rejected";

export type OkxDcdOrder = {
  orderId: string;
  productId: string;
  optionType: "call" | "put";
  state: OkxDcdOrderState;
  strike: string;
  principal: string;
  principalCurrency: string;
  annualizedYield: string;
  yieldAmount: string | null;
  yieldCurrency: string | null;
  createdAt: number;
  updatedAt: number;
  expiresAt: number;
  settledAt: number | null;
  settledAmount: string | null;
  settledCurrency: string | null;
  settlementPrice: string | null;
};

export type OkxIndexPrice = {
  instrumentId: string;
  price: string;
  updatedAt: number;
};

const REGIONS = new Set<OkxRegion>(["global", "us", "eu", "tr"]);
const ORDER_STATES = new Set<OkxDcdOrderState>([
  "initial",
  "live",
  "pending_settle",
  "settled",
  "pending_redeem",
  "redeemed",
  "rejected",
]);
const USD_STABLECOINS = new Set(["USD", "USDC", "USDT", "USDG", "DAI", "FDUSD", "TUSD", "PYUSD", "USDE"]);

export function createSingleFlight<T>(operation: () => Promise<T>): () => Promise<T> {
  let inFlight: Promise<T> | null = null;

  return () => {
    if (inFlight !== null) return inFlight;

    const request = operation();
    inFlight = request;
    const clear = () => {
      if (inFlight === request) inFlight = null;
    };
    void request.then(clear, clear);
    return request;
  };
}

function availableAmount(value: unknown, label: string): string {
  const amount = string(value, label);
  return amount === "" ? "0" : amount;
}

function optionalTimestamp(value: unknown, label: string): number | null {
  if (value === undefined || value === null || value === "") return null;
  return timestamp(value, label);
}

function parseOptionalCodeEnvelope(value: unknown, label: string): unknown[] {
  const envelope = record(value, label);
  if (envelope.code !== undefined) {
    const code = envelope.code === 0 ? "0" : string(envelope.code, `${label}.code`);
    if (code !== "0") {
      const message = string(envelope.msg, `${label}.msg`);
      throw new Error(`OKX API ${code}: ${message}`);
    }
  }
  return array(envelope.data, `${label}.data`);
}

export function parseOkxConnectionStatus(value: unknown): OkxConnectionStatus {
  const status = record(value, "OKX connection status");
  if (typeof status.configured !== "boolean") {
    throw new Error("OKX connection status.configured must be a boolean");
  }
  if (!status.configured) {
    if (status.apiKeyHint !== null || status.region !== null) {
      throw new Error("Unconfigured OKX status must not expose connection details");
    }
    return { configured: false, apiKeyHint: null, region: null };
  }
  const region = string(status.region, "OKX connection status.region") as OkxRegion;
  if (!REGIONS.has(region)) throw new Error("OKX connection status.region is invalid");
  return {
    configured: true,
    apiKeyHint: string(status.apiKeyHint, "OKX connection status.apiKeyHint"),
    region,
  };
}

export function parseOkxAssets(value: unknown): OkxAssets {
  const root = record(value, "OKX assets");
  const valuationRows = parseEnvelope(root.valuation, "OKX account valuation");
  if (valuationRows.length !== 1) {
    throw new Error("OKX account valuation must contain one summary");
  }
  const valuation = record(valuationRows[0], "OKX account valuation summary");
  const accountValues = record(valuation.details, "OKX account valuation summary.details");
  const tradingRows = parseEnvelope(root.trading, "OKX trading balance");
  if (tradingRows.length !== 1) {
    throw new Error("OKX trading balance must contain one account summary");
  }
  const summary = record(tradingRows[0], "OKX trading account summary");
  const details = array(summary.details, "OKX trading account summary.details");
  const trading: OkxAsset[] = details.map((value, index) => {
    const item = record(value, `OKX trading asset ${index}`);
    return {
      account: "trading",
      currency: string(item.ccy, `OKX trading asset ${index}.ccy`),
      balance: string(item.eq, `OKX trading asset ${index}.eq`),
      available: availableAmount(item.availEq, `OKX trading asset ${index}.availEq`),
      frozen: availableAmount(item.frozenBal, `OKX trading asset ${index}.frozenBal`),
      usdValue: optionalString(item.eqUsd, `OKX trading asset ${index}.eqUsd`),
    };
  });
  const funding = parseEnvelope(root.funding, "OKX funding balance").map((value, index) => {
    const item = record(value, `OKX funding asset ${index}`);
    return {
      account: "funding" as const,
      currency: string(item.ccy, `OKX funding asset ${index}.ccy`),
      balance: string(item.bal, `OKX funding asset ${index}.bal`),
      available: availableAmount(item.availBal, `OKX funding asset ${index}.availBal`),
      frozen: availableAmount(item.frozenBal, `OKX funding asset ${index}.frozenBal`),
      usdValue: null,
    };
  });
  return {
    totalEquityUsd: string(valuation.totalBal, "OKX account valuation summary.totalBal"),
    updatedAt: timestamp(valuation.ts, "OKX account valuation summary.ts"),
    accountValues: {
      funding: string(accountValues.funding, "OKX account valuation summary.details.funding"),
      trading: string(accountValues.trading, "OKX account valuation summary.details.trading"),
      earn: string(accountValues.earn, "OKX account valuation summary.details.earn"),
    },
    assets: [...trading, ...funding],
    tradingBalances: details.map((value, index) => {
      const label = `OKX trading asset ${index}`;
      const item = record(value, label);
      return {
        currency: string(item.ccy, `${label}.ccy`),
        spotBalance: optionalString(item.spotBal, `${label}.spotBal`),
        cashBalance: optionalString(item.cashBal, `${label}.cashBal`),
        available: optionalString(item.availBal, `${label}.availBal`),
        frozen: optionalString(item.frozenBal, `${label}.frozenBal`),
        liability: optionalString(item.liab, `${label}.liab`),
        interest: optionalString(item.interest, `${label}.interest`),
      };
    }),
  };
}

export function parseOkxDcdOrders(value: unknown): OkxDcdOrder[] {
  return parseOptionalCodeEnvelope(value, "OKX Dual Investment orders").map((value, index) => {
    const item = record(value, `OKX Dual Investment order ${index}`);
    const productId = string(item.productId, `OKX Dual Investment order ${index}.productId`);
    const optionType = productId.endsWith("-C")
      ? "call"
      : productId.endsWith("-P")
        ? "put"
        : null;
    if (optionType === null) {
      throw new Error(`OKX Dual Investment order ${index}.productId has no option type`);
    }
    const state = string(item.state, `OKX Dual Investment order ${index}.state`).toLowerCase() as OkxDcdOrderState;
    if (!ORDER_STATES.has(state)) {
      throw new Error(`OKX Dual Investment order ${index}.state is invalid`);
    }
    let principalCurrency: string;
    if (item.notionalCcy !== undefined) {
      principalCurrency = string(item.notionalCcy, `OKX Dual Investment order ${index}.notionalCcy`);
    } else {
      const productCurrencies = productId.split("-");
      if (productCurrencies.length < 2) {
        throw new Error(`OKX Dual Investment order ${index}.productId has no currency pair`);
      }
      principalCurrency = optionType === "call" ? productCurrencies[0] : productCurrencies[1];
    }
    const expiry = item.expTime !== undefined ? item.expTime : item.settleTime;
    const yieldAmount = optionalString(item.yieldSz, `OKX Dual Investment order ${index}.yieldSz`);
    const explicitYieldCurrency = optionalString(item.yieldCcy, `OKX Dual Investment order ${index}.yieldCcy`);
    const settledAmount = optionalString(item.settleSz, `OKX Dual Investment order ${index}.settleSz`);
    const settledCurrency = optionalString(item.settleCcy, `OKX Dual Investment order ${index}.settleCcy`);
    if (yieldAmount === null && explicitYieldCurrency !== null) {
      throw new Error(`OKX Dual Investment order ${index} has a yield currency without a yield amount`);
    }
    const yieldCurrency = yieldAmount === null
      ? null
      : explicitYieldCurrency ?? settledCurrency ?? principalCurrency;
    return {
      orderId: string(item.ordId, `OKX Dual Investment order ${index}.ordId`),
      productId,
      optionType,
      state,
      strike: string(item.strike, `OKX Dual Investment order ${index}.strike`),
      principal: string(item.notionalSz, `OKX Dual Investment order ${index}.notionalSz`),
      principalCurrency,
      annualizedYield: string(item.annualizedYield, `OKX Dual Investment order ${index}.annualizedYield`),
      yieldAmount,
      yieldCurrency,
      createdAt: timestamp(item.cTime, `OKX Dual Investment order ${index}.cTime`),
      updatedAt: timestamp(item.uTime, `OKX Dual Investment order ${index}.uTime`),
      expiresAt: timestamp(expiry, `OKX Dual Investment order ${index}.settleTime`),
      settledAt: optionalTimestamp(item.settleTime, `OKX Dual Investment order ${index}.settleTime`),
      settledAmount,
      settledCurrency,
      settlementPrice: optionalString(item.settlePx, `OKX Dual Investment order ${index}.settlePx`),
    };
  });
}

export function parseOkxIndexPrices(value: unknown): OkxIndexPrice[] {
  return parseEnvelope(value, "OKX index prices").map((value, index) => {
    const item = record(value, `OKX index price ${index}`);
    return {
      instrumentId: string(item.instId, `OKX index price ${index}.instId`),
      price: string(item.idxPx, `OKX index price ${index}.idxPx`),
      updatedAt: timestamp(item.ts, `OKX index price ${index}.ts`),
    };
  });
}

export function getOkxDcdIndexInstrumentId(productId: string): string {
  const [baseCurrency, quoteCurrency] = productId.split("-");
  if (baseCurrency === undefined || quoteCurrency === undefined) {
    throw new Error(`OKX Dual Investment product ${productId} has no currency pair`);
  }
  const indexBaseCurrency = baseCurrency === "BETH"
    ? "ETH"
    : baseCurrency === "OKSOL"
      ? "SOL"
      : baseCurrency;
  const indexQuoteCurrency = quoteCurrency === "USDG" ? "USD" : quoteCurrency;
  return `${indexBaseCurrency}-${indexQuoteCurrency}`;
}

export async function getOkxConnectionStatus(): Promise<OkxConnectionStatus> {
  return parseOkxConnectionStatus(await okxInvoke("okx_connection_status"));
}

export async function saveOkxCredentials(creds: OkxCredentialsInput): Promise<OkxConnectionStatus> {
  return parseOkxConnectionStatus(await okxInvoke("okx_save_credentials", { creds }));
}

export async function deleteOkxCredentials(): Promise<void> {
  await okxInvoke("okx_delete_credentials");
}

export async function getOkxAssets(): Promise<OkxAssets> {
  return parseOkxAssets(await okxInvoke("okx_get_assets"));
}

export async function getOkxDcdOrders(): Promise<OkxDcdOrder[]> {
  return parseOkxDcdOrders(await okxInvoke("okx_get_dcd_orders"));
}

export async function getOkxDcdIndexPrices(instrumentIds: string[]): Promise<OkxIndexPrice[]> {
  return parseOkxIndexPrices(await okxInvoke("okx_get_dcd_index_prices", { instrumentIds }));
}

export function isCurrentDcdOrder(order: OkxDcdOrder): boolean {
  return order.state === "initial"
    || order.state === "live"
    || order.state === "pending_settle"
    || order.state === "pending_redeem";
}

function addDecimalStrings(left: string, right: string, label: string): string {
  const decimal = /^-?\d+(?:\.\d+)?$/;
  if (!decimal.test(left) || !decimal.test(right)) {
    throw new Error(`${label} must contain decimal strings`);
  }
  const scaleOf = (value: string) => {
    const point = value.indexOf(".");
    return point === -1 ? 0 : value.length - point - 1;
  };
  const scale = Math.max(scaleOf(left), scaleOf(right));
  const toUnits = (value: string) => {
    const negative = value.startsWith("-");
    const unsigned = negative ? value.slice(1) : value;
    const parts = unsigned.split(".");
    const whole = parts[0];
    const fraction = parts.length === 2 ? parts[1] : "";
    const units = BigInt(`${whole}${fraction.padEnd(scale, "0")}`);
    return negative ? -units : units;
  };
  const total = toUnits(left) + toUnits(right);
  if (scale === 0) return total.toString();
  const negative = total < 0n;
  const digits = (negative ? -total : total).toString().padStart(scale + 1, "0");
  const whole = digits.slice(0, -scale);
  const fraction = digits.slice(-scale).replace(/0+$/, "");
  const sign = negative ? "-" : "";
  return fraction.length === 0 ? `${sign}${whole}` : `${sign}${whole}.${fraction}`;
}

function multiplyDecimalStrings(left: string, right: string, label: string): string {
  const decimal = /^-?\d+(?:\.\d+)?$/;
  if (!decimal.test(left) || !decimal.test(right)) {
    throw new Error(`${label} must contain decimal strings`);
  }
  const toParts = (value: string) => {
    const negative = value.startsWith("-");
    const unsigned = negative ? value.slice(1) : value;
    const [whole, fraction = ""] = unsigned.split(".");
    const units = BigInt(`${whole}${fraction}`);
    return { units: negative ? -units : units, scale: fraction.length };
  };
  const leftParts = toParts(left);
  const rightParts = toParts(right);
  const scale = leftParts.scale + rightParts.scale;
  const product = leftParts.units * rightParts.units;
  if (scale === 0) return product.toString();
  const negative = product < 0n;
  const digits = (negative ? -product : product).toString().padStart(scale + 1, "0");
  const whole = digits.slice(0, -scale);
  const fraction = digits.slice(-scale).replace(/0+$/, "");
  const sign = negative ? "-" : "";
  return fraction.length === 0 ? `${sign}${whole}` : `${sign}${whole}.${fraction}`;
}

function divideDecimalStrings(numerator: string, denominator: string, precision: number, label: string): string {
  const decimal = /^-?\d+(?:\.\d+)?$/;
  if (!decimal.test(numerator) || !decimal.test(denominator)) {
    throw new Error(`${label} must contain decimal strings`);
  }
  const toParts = (value: string) => {
    const negative = value.startsWith("-");
    const unsigned = negative ? value.slice(1) : value;
    const [whole, fraction = ""] = unsigned.split(".");
    return { negative, units: BigInt(`${whole}${fraction}`), scale: fraction.length };
  };
  const numeratorParts = toParts(numerator);
  const denominatorParts = toParts(denominator);
  if (denominatorParts.units === 0n) throw new Error(`${label} denominator must not be zero`);
  const scaledNumerator = numeratorParts.units * (10n ** BigInt(denominatorParts.scale + precision));
  const scaledDenominator = denominatorParts.units * (10n ** BigInt(numeratorParts.scale));
  const quotient = (scaledNumerator + (scaledDenominator / 2n)) / scaledDenominator;
  const digits = quotient.toString().padStart(precision + 1, "0");
  const whole = precision === 0 ? digits : digits.slice(0, -precision);
  const fraction = precision === 0 ? "" : digits.slice(-precision).replace(/0+$/, "");
  const sign = numeratorParts.negative !== denominatorParts.negative && quotient !== 0n ? "-" : "";
  return fraction.length === 0 ? `${sign}${whole}` : `${sign}${whole}.${fraction}`;
}

export function isUsdStablecoin(currency: string): boolean {
  return USD_STABLECOINS.has(currency.toUpperCase());
}

export function getOkxDcdRealizedYield(order: OkxDcdOrder): { amount: string; currency: string } | null {
  if (isCurrentDcdOrder(order)) return null;
  if (
    order.settledAmount !== null
    && order.settledCurrency !== null
    && order.settledCurrency === order.principalCurrency
  ) {
    const negativePrincipal = order.principal.startsWith("-") ? order.principal.slice(1) : `-${order.principal}`;
    return {
      amount: addDecimalStrings(order.settledAmount, negativePrincipal, `${order.orderId} realized yield`),
      currency: order.principalCurrency,
    };
  }
  if (order.yieldAmount === null || order.yieldCurrency === null) return null;
  return { amount: order.yieldAmount, currency: order.yieldCurrency };
}

export function estimateOkxDcdOrderYieldUsd(
  order: OkxDcdOrder,
  indexPrices: OkxIndexPrice[] | null,
): string | null {
  const realizedYield = getOkxDcdRealizedYield(order);
  if (realizedYield === null) return null;
  if (isUsdStablecoin(realizedYield.currency)) return realizedYield.amount;
  const [baseCurrency, quoteCurrency] = order.productId.split("-");
  if (baseCurrency === undefined || quoteCurrency === undefined) {
    throw new Error(`OKX Dual Investment product ${order.productId} has no currency pair`);
  }
  if (realizedYield.currency !== baseCurrency || !isUsdStablecoin(quoteCurrency)) return null;
  let price = order.settlementPrice;
  if (price === null && indexPrices !== null) {
    const instrumentId = getOkxDcdIndexInstrumentId(order.productId);
    const indexPrice = indexPrices.find((candidate) => candidate.instrumentId === instrumentId);
    if (indexPrice !== undefined) price = indexPrice.price;
  }
  if (price === null) return null;
  return multiplyDecimalStrings(realizedYield.amount, price, `${realizedYield.currency} yield USD value`);
}

export function sumOkxDcdYieldByCurrency(
  orders: OkxDcdOrder[],
  indexPrices: OkxIndexPrice[] | null,
): { currency: string; amount: string; usdValue: string | null }[] {
  const totals = new Map<string, { amount: string; usdValue: string | null; allPriced: boolean }>();
  for (const order of orders) {
    const realizedYield = getOkxDcdRealizedYield(order);
    if (realizedYield === null) continue;
    const usdValue = estimateOkxDcdOrderYieldUsd(order, indexPrices);
    const existing = totals.get(realizedYield.currency);
    totals.set(realizedYield.currency, {
      amount: existing === undefined
        ? addDecimalStrings("0", realizedYield.amount, `${realizedYield.currency} yield`)
        : addDecimalStrings(existing.amount, realizedYield.amount, `${realizedYield.currency} yield`),
      usdValue: existing === undefined
        ? usdValue
        : existing.usdValue !== null && usdValue !== null
          ? addDecimalStrings(existing.usdValue, usdValue, `${realizedYield.currency} yield USD value`)
          : null,
      allPriced: existing === undefined ? usdValue !== null : existing.allPriced && usdValue !== null,
    });
  }
  return [...totals.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([currency, total]) => ({
      currency,
      amount: total.amount,
      usdValue: total.allPriced ? total.usdValue : null,
    }));
}

export function sumOkxDcdYieldUsd(
  orders: OkxDcdOrder[],
  indexPrices: OkxIndexPrice[] | null,
): string | null {
  const totals = sumOkxDcdYieldByCurrency(orders, indexPrices);
  if (totals.length === 0) return null;
  let totalUsd: string | null = null;
  for (const total of totals) {
    if (total.usdValue === null) return null;
    totalUsd = totalUsd === null
      ? total.usdValue
      : addDecimalStrings(totalUsd, total.usdValue, "Dual Investment realized USD yield");
  }
  return totalUsd;
}

function okxDcdPrincipalUsdValue(order: OkxDcdOrder): string {
  if (isUsdStablecoin(order.principalCurrency)) return order.principal;
  const [baseCurrency, quoteCurrency] = order.productId.split("-");
  if (baseCurrency === undefined || quoteCurrency === undefined) {
    throw new Error(`OKX Dual Investment product ${order.productId} has no currency pair`);
  }
  if (order.principalCurrency !== baseCurrency || !isUsdStablecoin(quoteCurrency)) {
    throw new Error(`Cannot value ${order.principalCurrency} principal for ${order.productId}`);
  }
  return multiplyDecimalStrings(order.principal, order.strike, `${order.orderId} principal USD value`);
}

const MILLISECONDS_PER_YEAR = 365 * 24 * 60 * 60 * 1000;

function okxDcdRealizedAt(order: OkxDcdOrder): number {
  if (order.state === "settled") {
    if (order.settledAt === null) {
      throw new Error(`OKX Dual Investment order ${order.orderId} is settled without a settlement time`);
    }
    return order.settledAt;
  }
  if (order.state === "redeemed" || order.state === "rejected") return order.updatedAt;
  throw new Error(`OKX Dual Investment order ${order.orderId} is not a realized order`);
}

export function calculateOkxDcdRealizedApr(
  orders: OkxDcdOrder[],
  indexPrices: OkxIndexPrice[] | null,
): string | null {
  let totalYieldUsd = "0";
  let totalPrincipalTime = "0";
  let realizedOrderCount = 0;

  for (const order of orders) {
    const realizedYield = getOkxDcdRealizedYield(order);
    if (realizedYield === null) continue;
    const yieldUsd = estimateOkxDcdOrderYieldUsd(order, indexPrices);
    if (yieldUsd === null) return null;
    const endedAt = okxDcdRealizedAt(order);
    const heldMilliseconds = endedAt - order.createdAt;
    if (heldMilliseconds <= 0) {
      throw new Error(`OKX Dual Investment order ${order.orderId} holding time must be greater than zero`);
    }
    const principalTime = multiplyDecimalStrings(
      okxDcdPrincipalUsdValue(order),
      heldMilliseconds.toString(),
      `${order.orderId} principal time`,
    );
    totalYieldUsd = addDecimalStrings(totalYieldUsd, yieldUsd, "Dual Investment realized USD yield");
    totalPrincipalTime = addDecimalStrings(totalPrincipalTime, principalTime, "Dual Investment principal time");
    realizedOrderCount += 1;
  }

  if (realizedOrderCount === 0) return null;
  const annualizedYieldUsd = multiplyDecimalStrings(
    totalYieldUsd,
    MILLISECONDS_PER_YEAR.toString(),
    "Dual Investment annualized realized USD yield",
  );
  return divideDecimalStrings(annualizedYieldUsd, totalPrincipalTime, 12, "Dual Investment realized APR");
}

export function mergeOkxPortfolioAssets(
  assets: Pick<OkxAssets, "assets">,
  orders: OkxDcdOrder[],
  savings: OkxSaving[] = [],
): OkxPortfolioAsset[] {
  const portfolio = new Map<string, OkxPortfolioAsset & { available: string; frozen: string }>();

  for (const asset of assets.assets) {
    const existing = portfolio.get(asset.currency);
    if (existing === undefined) {
      portfolio.set(asset.currency, {
        accounts: [asset.account],
        currency: asset.currency,
        balance: asset.balance,
        available: asset.available,
        frozen: asset.frozen,
        usdValue: asset.usdValue,
      });
      continue;
    }
    if (!existing.accounts.includes(asset.account)) existing.accounts.push(asset.account);
    existing.balance = addDecimalStrings(existing.balance, asset.balance, `${asset.currency} balance`);
    existing.available = addDecimalStrings(existing.available, asset.available, `${asset.currency} available`);
    existing.frozen = addDecimalStrings(existing.frozen, asset.frozen, `${asset.currency} frozen`);
    if (existing.usdValue !== null && asset.usdValue !== null) {
      existing.usdValue = addDecimalStrings(existing.usdValue, asset.usdValue, `${asset.currency} USD value`);
    } else {
      existing.usdValue = null;
    }
  }

  for (const order of orders) {
    if (!isCurrentDcdOrder(order)) continue;
    const existing = portfolio.get(order.principalCurrency);
    if (existing === undefined) {
      portfolio.set(order.principalCurrency, {
        accounts: ["earn"],
        currency: order.principalCurrency,
        balance: order.principal,
        available: "0",
        frozen: order.principal,
        usdValue: null,
      });
      continue;
    }
    if (!existing.accounts.includes("earn")) existing.accounts.push("earn");
    existing.balance = addDecimalStrings(
      existing.balance,
      order.principal,
      `${order.principalCurrency} balance`,
    );
    existing.frozen = addDecimalStrings(
      existing.frozen,
      order.principal,
      `${order.principalCurrency} frozen`,
    );
    existing.usdValue = null;
  }

  const savingsOnly: OkxPortfolioAsset[] = [];
  for (const saving of savings) {
    if (Number(saving.balance) === 0) continue;
    const existing = portfolio.get(saving.currency);
    if (existing === undefined) {
      savingsOnly.push({
        accounts: ["earn"],
        currency: saving.currency,
        balance: saving.balance,
        available: null,
        frozen: null,
        usdValue: null,
      });
      continue;
    }
    if (!existing.accounts.includes("earn")) existing.accounts.push("earn");
    existing.balance = addDecimalStrings(existing.balance, saving.balance, `${saving.currency} balance`);
    existing.usdValue = null;
  }

  return [...portfolio.values(), ...savingsOnly];
}
