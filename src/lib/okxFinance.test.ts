import { expect, test } from "bun:test";
import { mergeOkxPortfolioAssets } from "./okxAccount";
import { getOkxLoanRisk, parseOkxFlexibleLoanRates, parseOkxFlexibleLoans, parseOkxSavings } from "./okxFinance";

const envelope = (data: unknown[]) => ({ code: "0", msg: "", data });
const savingsRows = [
  { ccy: "USDT", amt: "100.25", loanAmt: "80", pendingAmt: "20.25", earnings: "0.25", rate: "0.01" },
  { ccy: "ETH", amt: "0.5", loanAmt: "0.5", pendingAmt: "0", earnings: "0.001", rate: "0.03" },
];

test("matches the most recent actual lending APR by currency and keeps it distinct from the minimum APR", () => {
  const savings = parseOkxSavings({
    balances: envelope(savingsRows),
    history: { data: envelope([
      { ccy: "USDT", rate: "0.028", earnings: "0.004", ts: "1786973600000" },
      { ccy: "USDT", rate: "0.031", earnings: "0.005", ts: "1786970000000" },
      { ccy: "BTC", rate: "0.02", earnings: "0.000001", ts: "1786970000000" },
    ]) },
  });

  expect(savings.balances[0]).toEqual({
    currency: "USDT", balance: "100.25", lent: "80", pending: "20.25", earnings: "0.25", minimumApr: "0.01",
  });
  expect(savings.rates.data?.get("USDT")).toEqual({
    currency: "USDT", annualRate: "0.028", interest: "0.004", appliedAt: 1786973600000,
  });
  expect(savings.rates.data?.has("ETH")).toBe(false);
});

test("a lending history failure preserves balances and combines only the savings balance into holdings", () => {
  const savings = parseOkxSavings({ balances: envelope(savingsRows), history: { error: "OKX API 50038" } });
  expect(savings.rates).toEqual({ data: null, error: "OKX API 50038" });

  expect(mergeOkxPortfolioAssets({ assets: [
    { account: "funding", currency: "USDT", balance: "9.2", available: "8", frozen: "1.2", usdValue: null },
  ] }, [], savings.balances)).toEqual([
    { accounts: ["funding", "earn"], currency: "USDT", balance: "109.45", available: "8", frozen: "1.2", usdValue: null },
    { accounts: ["earn"], currency: "ETH", balance: "0.5", available: null, frozen: null, usdValue: null },
  ]);
});

const btcLoan = {
  ordId: "123",
  collateralData: [{ ccy: "BTC", amt: "0.1" }],
  loanData: [{ ccy: "USDT", amt: "3000" }],
  collateralNotionalUsd: "5000",
  loanNotionalUsd: "3000",
  curLTV: "0.6",
  marginCallLTV: "0.7",
  liqLTV: "0.8",
  riskWarningData: { instId: "BTC-USDT", liqPx: "42500.375" },
};

test("reads liquidation price in its pair and keeps multi-collateral risk visible without a price", () => {
  const loans = parseOkxFlexibleLoans({
    updatedAt: 1786977200000,
    loans: envelope([btcLoan, {
      ...btcLoan,
      ordId: "456",
      collateralData: [...btcLoan.collateralData, { ccy: "ETH", amt: "1.25" }],
      curLTV: "0.72",
      riskWarningData: { instId: "", liqPx: "" },
    }]),
  });

  expect(loans.updatedAt).toBe(1786977200000);
  expect(loans.orders[0].liquidation).toEqual({ instrumentId: "BTC-USDT", price: "42500.375" });
  expect(loans.orders[1].liquidation).toBeNull();
  expect(getOkxLoanRisk(loans.orders[0]).healthFactor).toBeCloseTo(4 / 3);
  expect(getOkxLoanRisk(loans.orders[0]).liquidationHeadroom).toBeCloseTo(0.2);
  expect(getOkxLoanRisk(loans.orders[1]).state).toBe("warning");
});

test("matches the latest recorded borrow APY to the correct order", () => {
  const rates = parseOkxFlexibleLoanRates([
    { orderId: "456", history: { data: envelope([{ ccy: "USDT", interestRate: "0.192", interest: "0.075", ts: "1786977200000" }]) } },
    { orderId: "123", history: { data: envelope([
      { ccy: "USDT", interestRate: "0.053", interest: "0.018", ts: "1786970000000" },
      { ccy: "USDT", interestRate: "0.062", interest: "0.021", ts: "1786973600000" },
    ]) } },
  ]);
  expect(rates.get("123")?.data?.get("USDT")?.annualRate).toBe("0.062");
  expect(rates.get("456")?.data?.get("USDT")?.annualRate).toBe("0.192");
});

test("risk remains available if borrowing interest fails, including at the exact liquidation threshold", () => {
  const { orders: [loan] } = parseOkxFlexibleLoans({
    updatedAt: 1786977200000,
    loans: envelope([{ ...btcLoan, curLTV: "0.8", loanNotionalUsd: "4000" }]),
  });
  const rates = parseOkxFlexibleLoanRates([{ orderId: "123", history: { error: "OKX API 50038" } }]);
  expect(rates.get(loan.orderId)).toEqual({ data: null, error: "OKX API 50038" });
  expect(getOkxLoanRisk(loan)).toEqual({ healthFactor: 1, state: "liquidation", liquidationHeadroom: 0 });
});

test("distinguishes an empty account from an invalid loan risk response", () => {
  const updatedAt = 1786977200000;
  expect(parseOkxFlexibleLoans({ updatedAt, loans: envelope([]) })).toEqual({ updatedAt, orders: [] });
  expect(parseOkxSavings({ balances: envelope([]), history: null })).toEqual({
    balances: [],
    rates: { data: new Map(), error: null },
  });
  expect(() => parseOkxFlexibleLoans({
    updatedAt, loans: envelope([{ ...btcLoan, curLTV: "" }]),
  })).toThrow("curLTV must be a non-negative decimal");
});
