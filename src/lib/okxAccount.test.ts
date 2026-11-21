import { describe, expect, test } from "bun:test";
import {
  calculateOkxDcdRealizedApr,
  createSingleFlight,
  getOkxDcdIndexInstrumentId,
  isCurrentDcdOrder,
  mergeOkxPortfolioAssets,
  parseOkxAssets,
  parseOkxDcdOrders,
  parseOkxIndexPrices,
  sumOkxDcdYieldByCurrency,
  sumOkxDcdYieldUsd,
  type OkxAssets,
} from "./okxAccount";

test("parses the OKX index price used by Dual Investment", () => {
  expect(parseOkxIndexPrices({
    code: "0",
    msg: "",
    data: [{
      instId: "BTC-USDC",
      idxPx: "64123.4567",
      high24h: "65000",
      low24h: "62000",
      open24h: "63000",
      sodUtc0: "63200",
      sodUtc8: "63100",
      ts: "1787100000123",
    }],
  })).toEqual([{
    instrumentId: "BTC-USDC",
    price: "64123.4567",
    updatedAt: 1787100000123,
  }]);
});

test("maps Dual Investment products to the index instruments OKX settles against", () => {
  expect(getOkxDcdIndexInstrumentId("BTC-USDC-260818-63750-C")).toBe("BTC-USDC");
  expect(getOkxDcdIndexInstrumentId("BETH-USDT-260818-5000-C")).toBe("ETH-USDT");
  expect(getOkxDcdIndexInstrumentId("OKSOL-USDG-260818-250-C")).toBe("SOL-USD");
});

test("shares one in-flight OKX refresh across duplicate callers", async () => {
  let calls = 0;
  let finish: ((value: string) => void) | undefined;
  const pending = new Promise<string>((resolve) => {
    finish = resolve;
  });
  const refresh = createSingleFlight(() => {
    calls += 1;
    return pending;
  });

  const first = refresh();
  const second = refresh();

  expect(first).toBe(second);
  expect(calls).toBe(1);
  if (finish === undefined) throw new Error("test refresh did not expose its resolver");
  finish("loaded");
  expect(await first).toBe("loaded");
});

test("portfolio BTC includes principal from OKX's uppercase LIVE Dual Investment state", () => {
  const assets: OkxAssets = {
    totalEquityUsd: "105236.00",
    updatedAt: 1786970060000,
    accountValues: { funding: "4.33", trading: "0.64", earn: "105231.02" },
    tradingBalances: [],
    assets: [{
      account: "funding",
      currency: "BTC",
      balance: "0.00006763",
      available: "0.00006763",
      frozen: "0",
      usdValue: null,
    }],
  };
  const [live, settled] = parseOkxDcdOrders({
    data: [
      {
        ordId: "live",
        productId: "BTC-USDT-260827-120000-C",
        state: "LIVE",
        strike: "120000",
        notionalSz: "0.9466",
        annualizedYield: "0.1748",
        expTime: "1787798400000",
        settleTime: "",
        cTime: "1786939200000",
        uTime: "1786970060000",
      },
      {
        ordId: "settled",
        productId: "BTC-USDT-260815-120000-C",
        state: "SETTLED",
        strike: "120000",
        notionalSz: "8",
        annualizedYield: "0.1",
        expTime: "1786760000000",
        settleTime: "1786760000000",
        cTime: "1786500800000",
        uTime: "1786760000000",
      },
    ],
  });

  expect(mergeOkxPortfolioAssets(assets, [live, settled])).toEqual([{
    accounts: ["funding", "earn"],
    currency: "BTC",
    balance: "0.94666763",
    available: "0.00006763",
    frozen: "0.9466",
    usdValue: null,
  }]);
});

test("all-order yield totals stay exact and keep currencies separate", () => {
  const orders = parseOkxDcdOrders({
    data: [
      {
        ordId: "btc-a",
        productId: "BTC-USDC-260817-63750-C",
        state: "SETTLED",
        strike: "63750",
        notionalSz: "0.946",
        annualizedYield: "0.118",
        yieldSz: "0.00059912",
        yieldCcy: "BTC",
        settlePx: "63490.15930194",
        settleCcy: "BTC",
        expTime: "1786982400000",
        settleTime: "1786982400000",
        cTime: "1786896000000",
        uTime: "1786982400000",
      },
      {
        ordId: "btc-b",
        productId: "BTC-USDC-260815-63750-C",
        state: "SETTLED",
        strike: "63750",
        notionalSz: "0.9453",
        annualizedYield: "0.2788",
        yieldSz: "0.00069209",
        yieldCcy: "BTC",
        settlePx: "63013.25304047",
        settleCcy: "BTC",
        expTime: "1786809600000",
        settleTime: "1786809600000",
        cTime: "1786723200000",
        uTime: "1786809600000",
      },
      {
        ordId: "usdc",
        productId: "BTC-USDC-260814-60000-P",
        state: "REDEEMED",
        strike: "60000",
        notionalSz: "1000",
        annualizedYield: "0.15",
        yieldSz: "12.50",
        yieldCcy: "USDC",
        expTime: "1787068800000",
        settleTime: "1786723200000",
        cTime: "1786636800000",
        uTime: "1786723200000",
      },
      {
        ordId: "live",
        productId: "BTC-USDC-260818-63750-C",
        state: "LIVE",
        strike: "63750",
        notionalSz: "0.9466",
        annualizedYield: "0.7354",
        expTime: "1787068800000",
        settleTime: "",
        cTime: "1786982400000",
        uTime: "1787025600000",
      },
    ],
  });

  expect(sumOkxDcdYieldByCurrency(orders, null)).toEqual([
    { currency: "BTC", amount: "0.00129121", usdValue: "81.6490665377571751" },
    { currency: "USDC", amount: "12.5", usdValue: "12.50" },
  ]);
});

test("sums realized yield across currencies into one USD total", () => {
  const orders = parseOkxDcdOrders({
    data: [
      {
        ordId: "btc",
        productId: "BTC-USDC-260817-63750-C",
        state: "SETTLED",
        strike: "63750",
        notionalSz: "0.5",
        annualizedYield: "0.118",
        yieldSz: "0.001",
        yieldCcy: "BTC",
        settlePx: "64000",
        settleCcy: "BTC",
        expTime: "1786982400000",
        settleTime: "1786982400000",
        cTime: "1786896000000",
        uTime: "1786982400000",
      },
      {
        ordId: "usdc",
        productId: "BTC-USDC-260814-60000-P",
        state: "REDEEMED",
        strike: "60000",
        notionalSz: "1000",
        annualizedYield: "0.15",
        yieldSz: "12.50",
        yieldCcy: "USDC",
        expTime: "1787068800000",
        settleTime: "1786723200000",
        cTime: "1786636800000",
        uTime: "1786723200000",
      },
      {
        ordId: "live",
        productId: "BTC-USDC-260818-63750-C",
        state: "LIVE",
        strike: "63750",
        notionalSz: "0.9466",
        annualizedYield: "0.7354",
        expTime: "1787068800000",
        settleTime: "",
        cTime: "1786982400000",
        uTime: "1787025600000",
      },
    ],
  });

  expect(sumOkxDcdYieldUsd(orders, null)).toBe("76.5");
  expect(sumOkxDcdYieldUsd([], null)).toBeNull();
});

test("USD total is unknown when any realized yield cannot be priced", () => {
  const [priced, unpriced] = parseOkxDcdOrders({
    data: [
      {
        ordId: "usdc",
        productId: "BTC-USDC-260814-60000-P",
        state: "REDEEMED",
        strike: "60000",
        notionalSz: "1000",
        annualizedYield: "0.15",
        yieldSz: "12.50",
        yieldCcy: "USDC",
        expTime: "1787068800000",
        settleTime: "1786723200000",
        cTime: "1786636800000",
        uTime: "1786723200000",
      },
      {
        ordId: "eth-no-price",
        productId: "ETH-USDC-260817-3000-C",
        state: "SETTLED",
        strike: "3000",
        notionalSz: "2",
        annualizedYield: "0.2",
        yieldSz: "0.01",
        yieldCcy: "ETH",
        settleCcy: "ETH",
        expTime: "1786982400000",
        settleTime: "1786982400000",
        cTime: "1786896000000",
        uTime: "1786982400000",
      },
    ],
  });

  expect(sumOkxDcdYieldUsd([priced], null)).toBe("12.50");
  expect(sumOkxDcdYieldUsd([priced, unpriced], null)).toBeNull();
});

test("realized APR uses actual yield and held time instead of the quoted APR", () => {
  const [order] = parseOkxDcdOrders({
    data: [{
      ordId: "settled-realized",
      productId: "BTC-USDC-260818-60000-P",
      state: "SETTLED",
      strike: "60000",
      notionalSz: "1000",
      notionalCcy: "USDC",
      annualizedYield: "0.99",
      yieldSz: "10",
      yieldCcy: "USDC",
      expTime: "1787068800000",
      settleTime: "1787068800000",
      cTime: "1783915200000",
      uTime: "1787068800000",
    }],
  });

  expect(calculateOkxDcdRealizedApr([order], null)).toBe("0.1");
  expect(calculateOkxDcdRealizedApr([{ ...order, state: "live", annualizedYield: "9.99" }, order], null)).toBe("0.1");
  expect(calculateOkxDcdRealizedApr([], null)).toBeNull();
});

test("realized APR includes the net result of an early redemption", () => {
  const [order] = parseOkxDcdOrders({
    data: [{
      ordId: "redeemed-with-penalty",
      productId: "BTC-USDC-260818-60000-P",
      state: "REDEEMED",
      strike: "60000",
      notionalSz: "1000",
      notionalCcy: "USDC",
      annualizedYield: "0.5",
      yieldSz: "5",
      yieldCcy: "USDC",
      settleSz: "990",
      settleCcy: "USDC",
      expTime: "1787068800000",
      settleTime: "1784779200000",
      cTime: "1783915200000",
      uTime: "1784779200000",
    }],
  });

  expect(calculateOkxDcdRealizedApr([order], null)).toBe("-0.365");
  expect(sumOkxDcdYieldByCurrency([order], null)).toEqual([
    { currency: "USDC", amount: "-10", usdValue: "-10" },
  ]);
});

test("redeemed APR uses the actual redemption time instead of the scheduled expiry", () => {
  const [order] = parseOkxDcdOrders({
    data: [{
      ordId: "redeemed-before-expiry",
      productId: "BTC-USDC-260925-60000-P",
      state: "REDEEMED",
      strike: "60000",
      notionalSz: "10000",
      notionalCcy: "USDC",
      annualizedYield: "0.5",
      yieldSz: "10",
      yieldCcy: "USDC",
      settleSz: "10010",
      settleCcy: "USDC",
      expTime: "1790352000000",
      settleTime: "1790352000000",
      cTime: "1786636800000",
      uTime: "1786723200000",
    }],
  });

  expect(calculateOkxDcdRealizedApr([order], null)).toBe("0.365");
});

test("an empty OKX available amount does not crash portfolio rendering", () => {
  const assets = parseOkxAssets({
    valuation: {
      code: "0",
      msg: "",
      data: [{
        totalBal: "0.64",
        ts: "1786970060000",
        details: { funding: "0", trading: "0.64", earn: "0" },
      }],
    },
    trading: {
      code: "0",
      msg: "",
      data: [{
        details: [{
          ccy: "USDC",
          eq: "0.644713",
          availEq: "",
          frozenBal: "0",
          eqUsd: "0.64",
        }],
      }],
    },
    funding: { code: "0", msg: "", data: [] },
  });

  const [usdc] = mergeOkxPortfolioAssets(assets, []);

  expect(usdc.available).toBe("0");
  expect(usdc.balance).toBe("0.644713");
});

describe("OKX account response parsing", () => {
  test("keeps trading and funding balances distinct", () => {
    const parsed = parseOkxAssets({
      valuation: {
        code: "0",
        msg: "",
        data: [{
          totalBal: "105160.55",
          ts: "1786970060000",
          details: {
            funding: "4.32",
            trading: "0.64",
            classic: "0",
            earn: "105155.59",
          },
        }],
      },
      trading: {
        code: "0",
        msg: "",
        data: [{
          totalEq: "12543.21",
          uTime: "1786970000000",
          details: [{
            ccy: "BTC",
            eq: "0.125",
            spotBal: "0.12",
            cashBal: "0.11",
            availEq: "0.1",
            availBal: "0.08",
            liab: "0.015",
            interest: "0.000001",
            frozenBal: "0.025",
            eqUsd: "8500.50",
          }],
        }],
      },
      funding: {
        code: "0",
        msg: "",
        data: [{ ccy: "USDT", bal: "4042.71", availBal: "4000", frozenBal: "42.71" }],
      },
    });

    expect(parsed.totalEquityUsd).toBe("105160.55");
    expect(parsed.updatedAt).toBe(1786970060000);
    expect(parsed.accountValues).toEqual({
      funding: "4.32",
      trading: "0.64",
      earn: "105155.59",
    });
    expect(parsed.assets).toEqual([
      {
        account: "trading",
        currency: "BTC",
        balance: "0.125",
        available: "0.1",
        frozen: "0.025",
        usdValue: "8500.50",
      },
      {
        account: "funding",
        currency: "USDT",
        balance: "4042.71",
        available: "4000",
        frozen: "42.71",
        usdValue: null,
      },
    ]);
    expect(parsed.tradingBalances).toEqual([{
      currency: "BTC",
      spotBalance: "0.12",
      cashBalance: "0.11",
      available: "0.08",
      frozen: "0.025",
      liability: "0.015",
      interest: "0.000001",
    }]);
  });

  test("parses a live Dual Investment order and rejects missing yield", () => {
    const payload = {
      code: "0",
      msg: "",
      data: [{
        ordId: "987654321",
        productId: "BTC-USDT-260827-120000-C",
        state: "live",
        strike: "120000",
        notionalSz: "0.1",
        notionalCcy: "BTC",
        annualizedYield: "0.1748",
        yieldSz: "0.000335",
        yieldCcy: "BTC",
        expTime: "1787798400000",
        settleTime: "",
        cTime: "1786939200000",
        uTime: "1786970060000",
        settleSz: "",
        settleCcy: "",
        settlePx: "",
      }],
    };
    const [order] = parseOkxDcdOrders(payload);
    expect(order.annualizedYield).toBe("0.1748");
    expect(order.optionType).toBe("call");
    expect(isCurrentDcdOrder(order)).toBe(true);

    const withoutYield = structuredClone(payload);
    delete (withoutYield.data[0] as Record<string, unknown>).annualizedYield;
    expect(() => parseOkxDcdOrders(withoutYield)).toThrow("annualizedYield must be a string");
  });

  test("parses the code-less Dual Investment history shape returned by OKX", () => {
    const [order] = parseOkxDcdOrders({
      data: [{
        ordId: "123",
        productId: "BTC-USDT-260827-120000-C",
        state: "live",
        baseCcy: "BTC",
        quoteCcy: "USDT",
        strike: "120000",
        notionalSz: "0.9466",
        annualizedYield: "0.1748",
        yieldSz: "0.00059912",
        expTime: "1787798400000",
        settleTime: "",
        cTime: "1786939200000",
        uTime: "1786970060000",
      }],
    });

    expect(order.principalCurrency).toBe("BTC");
    expect(order.yieldCurrency).toBe("BTC");
    expect(order.expiresAt).toBe(1787798400000);
  });

  test("parses a Dual Investment response with OKX's numeric success code", () => {
    const [order] = parseOkxDcdOrders({
      code: 0,
      msg: "",
      data: [{
        ordId: "456",
        productId: "BTC-USDT-260827-120000-C",
        state: "live",
        strike: "120000",
        notionalSz: "0.9466",
        notionalCcy: "BTC",
        annualizedYield: "0.1748",
        expTime: "1787798400000",
        settleTime: "",
        cTime: "1786939200000",
        uTime: "1786970060000",
      }],
    });

    expect(order.orderId).toBe("456");
    expect(order.principal).toBe("0.9466");
  });
});
