import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import type { OkxDcdOrder, OkxIndexPrice, OkxPortfolioAsset } from "../lib/okxAccount";

const store = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
  getItem: (key: string) => store.get(key) ?? null,
  setItem: (key: string, value: string) => void store.set(key, value),
  removeItem: (key: string) => void store.delete(key),
  clear: () => store.clear(),
  key: () => null,
  length: 0,
} as Storage;

const { AssetTable, OrderHeadActions, OrderList, OrderYieldSummary } = await import("./OkxPage");
const { FlexibleLoanSection, SavingsTable, TradingBalanceTable } = await import("./OkxFinance");

test("shows liquidation risk, the quoted price, and available borrow rates per loan", () => {
  const first = {
    orderId: "123",
    collateral: [{ currency: "BTC", amount: "0.1" }],
    debts: [{ currency: "USDT", amount: "3000" }],
    adjustedCollateralUsd: "5000",
    debtUsd: "3000",
    currentLtv: 0.6,
    marginCallLtv: 0.7,
    liquidationLtv: 0.8,
    liquidation: { instrumentId: "BTC-USDT", price: "42500.375" },
  };
  const second = {
    ...first,
    orderId: "456",
    collateral: [...first.collateral, { currency: "ETH", amount: "1" }],
    currentLtv: 0.72,
    liquidation: null,
  };
  const updatedAt = 1786977200000;
  const loans = { updatedAt, orders: [first, second] };
  const pending = renderToStaticMarkup(<FlexibleLoanSection loans={loans} loanRates={null} rateError={null} error={null} />);
  expect(pending).toContain("42,500.375 USDT");
  expect(pending).toContain('class="okx-ltv-marker" style="left:60%"');
  expect(pending).toContain('data-risk="warning"');
  expect(pending).toContain("1.33");
  expect(pending).toContain("Multi-asset loan with no single liquidation price");

  const actual = renderToStaticMarkup(<FlexibleLoanSection loans={loans} rateError={null} error={null} loanRates={new Map([
    ["123", { data: new Map([["USDT", { currency: "USDT", annualRate: "0.062", interest: "0.021", appliedAt: updatedAt }]]), error: null }],
    ["456", { data: null, error: "OKX test rate history unavailable" }],
  ])} />);
  expect(actual).toContain("Last borrow APY 6.2%");
  expect(actual).toContain("Last interest 0.021");
  expect(actual).toContain("Borrowing rate history unavailable.");
  expect(actual).toContain("42,500.375 USDT");
});

test("renders the spot balance and Earn holdings as separate account data", () => {
  const trading = renderToStaticMarkup(<TradingBalanceTable balances={[
    { currency: "BTC", spotBalance: "0.125", cashBalance: "0.14", available: "0.1", frozen: "0.02", liability: "0.035", interest: "0.000001" },
  ]} />);
  expect(trading).toContain("Spot balance");
  expect(trading).toContain(">0.125<");
  expect(trading).toContain("Trading liabilities");
  expect(trading).toContain(">0.035<");

  const savings = renderToStaticMarkup(<SavingsTable error={null} savings={{
    balances: [{ currency: "USDT", balance: "100.25", lent: "80", pending: "20.25", earnings: "0.25", minimumApr: "0.01" }],
    rates: { data: new Map([["USDT", { currency: "USDT", annualRate: "0.028", interest: "0.004", appliedAt: 1786977200000 }]]), error: null },
  }} />);
  expect(savings).toContain("Last lending APR");
  expect(savings).toContain(">2.8%<");
  expect(savings).toContain(">1%<");
  expect(savings).toContain(">100.25<");
  expect(savings).toContain(">20.25<");
});

const settledOrder: OkxDcdOrder = {
  orderId: "10957529",
  productId: "BTC-USDC-260818-63750-C",
  optionType: "call",
  state: "settled",
  strike: "63750",
  principal: "0.9466",
  principalCurrency: "BTC",
  annualizedYield: "0.7354",
  yieldAmount: "0.00123456",
  yieldCurrency: "BTC",
  createdAt: 1786982400000,
  updatedAt: 1787068800000,
  expiresAt: 1787068800000,
  settledAt: 1787068800000,
  settledAmount: "60348.75",
  settledCurrency: "USDC",
  settlementPrice: "64120.5",
};

const btcUsdcIndexPrice: OkxIndexPrice = {
  instrumentId: "BTC-USDC",
  price: "64123.4567",
  updatedAt: 1787100000123,
};

describe("OKX Dual Investment table", () => {
  test("offers CSV export for current holdings and disables export without orders", () => {
    const renderActions = (allOrders: OkxDcdOrder[] | null) => renderToStaticMarkup(
      <OrderHeadActions allOrders={allOrders} indexPrices={null} showAllOrders={false} onShowAllOrders={() => {}} />,
    );
    expect(renderActions([settledOrder])).toContain('class="okx-csv-button" title=');
    expect(renderActions([settledOrder])).toContain("Download CSV");
    expect(renderActions(null)).toContain('class="okx-csv-button" disabled=""');
    expect(renderActions([])).toContain('class="okx-csv-button" disabled=""');
  });
  test("shows the OKX index price used by Dual Investment instead of a spot price", () => {
    const html = renderToStaticMarkup(
      <OrderList orders={[settledOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );

    expect(html).toContain("Index price");
    expect(html).toContain("64,123.46 USDC");
    expect(html).toContain("Dual Investment references the OKX index price, not the spot last-traded price");
    expect(html).not.toContain("Spot price");
  });

  test("keeps the yield summary visible for current holdings", () => {
    const currentOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "current",
      state: "live",
      annualizedYield: "0.8273",
      yieldAmount: null,
      yieldCurrency: null,
      settledAmount: null,
      settledCurrency: null,
      settlementPrice: null,
      settledAt: null,
    };
    const html = renderToStaticMarkup(
      <OrderHeadActions
        allOrders={[currentOrder, settledOrder]}
        indexPrices={null}
        showAllOrders={false}
        onShowAllOrders={() => {}}
      />,
    );

    expect(html).toContain("okx-order-yield-summary");
    expect(html).toContain("+0.001235 BTC");
    expect(html).toContain("47.88%");
    expect(html).not.toContain("82.73%");
    expect(html).toContain('<button class="on">Current</button>');
  });

  test("shows every order field in a table instead of cards", () => {
    const html = renderToStaticMarkup(
      <OrderList orders={[settledOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );

    expect(html).toContain("<table");
    expect(html).toContain("okx-order-table");
    expect(html).not.toContain("okx-order-card");
    expect(html).toContain("<th>APR</th>");
    expect(html).not.toContain("Annualized yield");
    expect(html).toContain("BTC-USDC-260818-63750-C");
    expect(html).toContain("10957529");
    expect(html).toContain("73.54%");
    expect(html).toContain("0.946600 BTC");
    expect(html).toContain("63,750.00 USDC");
    expect(html).toContain("0.001235 BTC");
    expect(html).toContain("60,348.75");
    expect(html).toContain("64,120.50");
    expect(html).toContain("Settled");
    expect(html).toContain("($79.16)");
    expect(html).not.toContain("<th>Subscribed</th>");
    expect(html).toContain("okx-order-timeline");
    expect(html).toContain("Subscribed");
    expect(html).toContain("Expiry");
    expect(html).toContain('dateTime="2026-08-17T16:00:00.000Z"');
    const yieldCellStart = html.indexOf('class="okx-order-yield-cell"');
    const yieldCellEnd = html.indexOf("</td>", yieldCellStart);
    const yieldCell = html.slice(yieldCellStart, yieldCellEnd);
    const timelineStart = html.indexOf('class="okx-order-timeline"');
    const timelineEnd = html.indexOf("</td>", timelineStart);
    const timelineCell = html.slice(timelineStart, timelineEnd);
    expect(yieldCell).toContain('class="okx-state settled"');
    expect(timelineCell).not.toContain("okx-state");
    expect(html).not.toContain("okx-order-yield-summary");
  });

  test("renders the all-order yield summary above the table", () => {
    const html = renderToStaticMarkup(<OrderYieldSummary orders={[settledOrder]} indexPrices={null} />);

    expect(html).toContain("okx-order-yield-summary");
    expect(html).toContain("Total yield");
    expect(html).toContain("Average APR");
    expect(html).toContain("47.88%");
    expect(html).toContain("+0.001235 BTC");
    expect(html).toContain("($79.16)");
  });

  test("uses the current index price when realized crypto yield has no settlement price", () => {
    const unpricedEthOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "11052423",
      productId: "ETH-USDC-260817-3000-C",
      strike: "3000",
      principal: "2",
      principalCurrency: "ETH",
      yieldAmount: "0.01",
      yieldCurrency: "ETH",
      settledAmount: null,
      settledCurrency: null,
      settlementPrice: null,
    };
    const ethUsdcIndexPrice: OkxIndexPrice = {
      instrumentId: "ETH-USDC",
      price: "2412.38",
      updatedAt: 1787100000123,
    };

    const html = renderToStaticMarkup(
      <OrderYieldSummary orders={[unpricedEthOrder]} indexPrices={[ethUsdcIndexPrice]} />,
    );

    expect(html).toContain("okx-order-yield-summary");
    expect(html).toContain("+0.010000 ETH");
    expect(html).toContain("($24.12)");
    expect(html).toContain("146.75%");
  });

  test("shows one USD total for all realized yield next to the per-currency breakdown", () => {
    const btcOrder = { ...settledOrder, yieldAmount: "0.00508687" };
    const usdcOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "usdc-yield",
      optionType: "put",
      principal: "60462",
      principalCurrency: "USDC",
      yieldAmount: "164.80074235",
      yieldCurrency: "USDC",
      settledAmount: "60626.80074235",
      settledCurrency: "USDC",
    };
    const html = renderToStaticMarkup(<OrderYieldSummary orders={[btcOrder, usdcOrder]} indexPrices={null} />);

    expect(html).toContain('class="okx-order-yield-summary-total tnum">+$490.97<');
    expect(html).toContain("+0.005087 BTC");
    expect(html).toContain("+164.80 USDC");
    expect(html).toContain("By currency");
  });

  test("shows a negative USD total for a net loss", () => {
    const redeemedOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "redeemed-btc-penalty",
      state: "redeemed",
      settledAmount: "0.9366",
      settledCurrency: "BTC",
    };
    const html = renderToStaticMarkup(<OrderYieldSummary orders={[redeemedOrder]} indexPrices={null} />);

    expect(html).toContain('class="okx-order-yield-summary-total tnum down">-$641.21<');
  });

  test("shows a dash for the USD total when nothing has been realized", () => {
    const currentOrder: OkxDcdOrder = {
      ...settledOrder,
      state: "live",
      yieldAmount: null,
      yieldCurrency: null,
      settledAmount: null,
      settledCurrency: null,
      settlementPrice: null,
      settledAt: null,
    };
    const html = renderToStaticMarkup(<OrderYieldSummary orders={[currentOrder]} indexPrices={null} />);

    expect(html).toContain('class="okx-order-yield-summary-total okx-order-empty">—<');
    expect(html).not.toContain("By currency");
  });

  test("keeps the order tabs on one line however wide the yield summary gets", () => {
    const css = readFileSync(new URL("./OkxPage.css", import.meta.url), "utf8");

    expect(css).toContain(".okx-segmented {\n  flex: none;");
    expect(css).toContain(".okx-segmented button {\n  white-space: nowrap;");
    expect(css).toContain(".okx-order-head-actions {\n  display: flex;\n  flex-wrap: wrap;");
    expect(css).toContain(".okx-order-yield-summary {\n  flex: 1 1 0;\n  min-width: min-content;\n  max-width: max-content;");
    expect(css).toContain(".okx-order-yield-summary-breakdown {\n  min-width: min-content;");
  });

  test("formats stablecoin totals to two decimals and other totals to six", () => {
    const btcOrder = { ...settledOrder, yieldAmount: "0.00508687" };
    const usdcOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "usdc-yield",
      optionType: "put",
      principal: "60462",
      principalCurrency: "USDC",
      yieldAmount: "164.80074235",
      yieldCurrency: "USDC",
      settledAmount: "60626.80074235",
      settledCurrency: "USDC",
    };
    const html = renderToStaticMarkup(<OrderYieldSummary orders={[btcOrder, usdcOrder]} indexPrices={null} />);

    expect(html).toContain("+0.005087 BTC");
    expect(html).toContain("+164.80 USDC");
    expect(html).not.toContain("0.00508687 BTC");
    expect(html).not.toContain("164.80074235 USDC");
  });

  test("formats every table currency amount by asset type", () => {
    const html = renderToStaticMarkup(
      <OrderList orders={[settledOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );

    expect(html).toContain("0.946600 BTC");
    expect(html).toContain("+0.001235 BTC");
    expect(html).toContain("60,348.75 USDC");
    expect(html).toContain("63,750.00 USDC");
    expect(html).toContain("64,123.46 USDC");
    expect(html).toContain("64,120.50 USDC");
    expect(html).not.toContain("0.00123456 BTC");
    expect(html).not.toContain("64,123.4567 USDC");
  });

  test("shows an early redemption penalty as a negative realized yield", () => {
    const redeemedOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "redeemed-with-penalty",
      optionType: "put",
      state: "redeemed",
      principal: "1000",
      principalCurrency: "USDC",
      yieldAmount: "5",
      yieldCurrency: "USDC",
      settledAmount: "990",
      settledCurrency: "USDC",
    };

    const listHtml = renderToStaticMarkup(
      <OrderList orders={[redeemedOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );
    const summaryHtml = renderToStaticMarkup(<OrderYieldSummary orders={[redeemedOrder]} indexPrices={null} />);

    expect(listHtml).toContain("-10.00 USDC");
    expect(listHtml).not.toContain("+-10.00 USDC");
    expect(summaryHtml).toContain("-10.00 USDC");
  });

  test("shows only the status when a current order has no realized yield", () => {
    const currentOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "current-without-yield",
      state: "live",
      yieldAmount: null,
      yieldCurrency: null,
      settledAmount: null,
      settledCurrency: null,
      settlementPrice: null,
      settledAt: null,
    };

    const html = renderToStaticMarkup(
      <OrderList orders={[currentOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );
    const yieldCellStart = html.indexOf('class="okx-order-yield-cell"');
    const yieldCellEnd = html.indexOf("</td>", yieldCellStart);
    const yieldCell = html.slice(yieldCellStart, yieldCellEnd);

    expect(yieldCell).toContain("Earning");
    expect(yieldCell).not.toContain("okx-order-empty");
    expect(yieldCell).not.toContain("—");
  });

  test("shows the actual redemption time instead of the scheduled expiry", () => {
    const redeemedOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "redeemed-before-expiry",
      state: "redeemed",
      updatedAt: 1786723200000,
      expiresAt: 1790352000000,
      settledAt: 1790352000000,
    };

    const html = renderToStaticMarkup(
      <OrderList orders={[redeemedOrder]} indexPrices={[btcUsdcIndexPrice]} priceError={null} />,
    );

    expect(html).toContain('dateTime="2026-08-14T16:00:00.000Z"');
    expect(html).not.toContain('dateTime="2026-09-25T16:00:00.000Z"');
  });

  test("formats a non-stablecoin penalty with a readable negative USD estimate", () => {
    const redeemedOrder: OkxDcdOrder = {
      ...settledOrder,
      orderId: "redeemed-btc-penalty",
      state: "redeemed",
      settledAmount: "0.9366",
      settledCurrency: "BTC",
    };

    const html = renderToStaticMarkup(<OrderYieldSummary orders={[redeemedOrder]} indexPrices={null} />);

    expect(html).toContain("-0.010000 BTC");
    expect(html).toContain("(-$641.21)");
    expect(html).not.toContain("($-641.21)");
  });

  test("reserves more table width for yield, settlement, and status details", () => {
    const css = readFileSync(new URL("./OkxPage.css", import.meta.url), "utf8");

    expect(css).toContain("min-width: 960px");
    expect(css).toContain(".okx-order-table th:first-child {\n  width: 18%");
    expect(css).toContain(".okx-order-table th:nth-child(2) { width: 7%; }");
    expect(css).toContain(".okx-order-table th:nth-child(6) { width: 17%; }");
  });

  test("uses a warm warning tint for redeemed orders", () => {
    const css = readFileSync(new URL("./OkxPage.css", import.meta.url), "utf8");

    expect(css).toContain(".okx-state.redeemed { color: var(--warn); background: var(--warn-soft); }");
  });

  test("formats the asset table with the same stablecoin and crypto precision", () => {
    const assets: OkxPortfolioAsset[] = [
      {
        currency: "USDC",
        accounts: ["trading", "earn"],
        available: "0.02370256",
        frozen: "44888",
        balance: "44888.66841556",
        usdValue: "44888.66841556",
      },
      {
        currency: "BTC",
        accounts: ["funding"],
        available: "0.00006763",
        frozen: "0.9466",
        balance: "0.94666763",
        usdValue: "60911.22",
      },
    ];

    const html = renderToStaticMarkup(<AssetTable assets={assets} />);

    expect(html).toContain("0.02");
    expect(html).toContain("44,888.00");
    expect(html).toContain("44,888.67");
    expect(html).toContain("0.000068");
    expect(html).toContain("0.946600");
    expect(html).toContain("0.946668");
    expect(html).not.toContain("44,888.66841556");
    expect(html).not.toContain("0.94666763");
  });
});
