import { array, okxInvoke, optionalString, parseEnvelope, record, string, timestamp } from "./okxResponse";

type FinanceResult<T> = { data: T; error: null } | { data: null; error: string };

type AppliedRate = {
  currency: string;
  annualRate: string;
  interest: string;
  appliedAt: number;
};

export type OkxAppliedRates = FinanceResult<Map<string, AppliedRate>>;
export type OkxLoanRates = Map<string, OkxAppliedRates>;

export type OkxSaving = {
  currency: string;
  balance: string;
  lent: string;
  pending: string;
  earnings: string;
  minimumApr: string;
};

export type OkxSavings = {
  balances: OkxSaving[];
  rates: OkxAppliedRates;
};

type CoinAmount = { currency: string; amount: string };

export type OkxFlexibleLoan = {
  orderId: string;
  collateral: CoinAmount[];
  debts: CoinAmount[];
  adjustedCollateralUsd: string;
  debtUsd: string;
  currentLtv: number;
  marginCallLtv: number;
  liquidationLtv: number;
  liquidation: { instrumentId: string; price: string } | null;
};

export type OkxFlexibleLoans = {
  updatedAt: number;
  orders: OkxFlexibleLoan[];
};

function decimal(value: unknown, label: string): string {
  const amount = string(value, label);
  if (!/^(?:\d+\.?\d*|\.\d+)$/.test(amount) || !Number.isFinite(Number(amount))) {
    throw new Error(`${label} must be a non-negative decimal`);
  }
  return amount;
}

// The rate history is supplementary. Surface its errors alongside the
// balances or risk data so a failed history read cannot hide them.
function parseRateHistory(value: unknown, kind: "lending" | "borrowing"): OkxAppliedRates {
  const label = `OKX ${kind} rate history`;
  try {
    const result = record(value, label);
    if ("error" in result) return { data: null, error: string(result.error, `${label}.error`) };
    const rates = new Map<string, AppliedRate>();
    for (const value of parseEnvelope(result.data, label)) {
      const row = record(value, label);
      const currency = string(row.ccy, `${label}.ccy`);
      const annualRate = kind === "lending" ? row.rate : row.interestRate;
      const interest = kind === "lending" ? row.earnings : row.interest;
      const appliedAt = timestamp(row.ts, `${label}.ts`);
      const previous = rates.get(currency);
      if (previous !== undefined && previous.appliedAt >= appliedAt) continue;
      rates.set(currency, {
        currency,
        annualRate: decimal(annualRate, `${label} annual rate`),
        interest: decimal(interest, `${label} interest`),
        appliedAt,
      });
    }
    return { data: rates, error: null };
  } catch (error) {
    return { data: null, error: String(error) };
  }
}

export function parseOkxSavings(value: unknown): OkxSavings {
  const root = record(value, "OKX savings");
  const balances = parseEnvelope(root.balances, "OKX savings balances").map((value, index) => {
    const label = `OKX savings balance ${index}`;
    const row = record(value, label);
    return {
      currency: string(row.ccy, `${label}.ccy`),
      balance: decimal(row.amt, `${label}.amt`),
      lent: decimal(row.loanAmt, `${label}.loanAmt`),
      pending: decimal(row.pendingAmt, `${label}.pendingAmt`),
      earnings: decimal(row.earnings, `${label}.earnings`),
      minimumApr: decimal(row.rate, `${label}.rate`),
    };
  });
  const rates = balances.length === 0 && root.history === null
    ? { data: new Map<string, AppliedRate>(), error: null }
    : parseRateHistory(root.history, "lending");
  return { balances, rates };
}

function parseCoinAmounts(value: unknown, label: string): CoinAmount[] {
  return array(value, label).map((value, index) => {
    const row = record(value, `${label}.${index}`);
    return {
      currency: string(row.ccy, `${label}.${index}.ccy`),
      amount: decimal(row.amt, `${label}.${index}.amt`),
    };
  });
}

export function parseOkxFlexibleLoans(value: unknown): OkxFlexibleLoans {
  const root = record(value, "OKX flexible loans");
  if (typeof root.updatedAt !== "number" || !Number.isSafeInteger(root.updatedAt) || root.updatedAt <= 0) {
    throw new Error("OKX flexible loans.updatedAt is invalid");
  }
  const orders = parseEnvelope(root.loans, "OKX flexible loan orders").map((value, index): OkxFlexibleLoan => {
    const label = `OKX flexible loan ${index}`;
    const row = record(value, label);
    const orderId = string(row.ordId, `${label}.ordId`);
    const warning = record(row.riskWarningData, `${label}.riskWarningData`);
    const instrumentId = optionalString(warning.instId, `${label}.instId`);
    const price = optionalString(warning.liqPx, `${label}.liqPx`);
    if ((instrumentId === null) !== (price === null)) {
      throw new Error(`${label} has incomplete liquidation price data`);
    }
    const currentLtv = Number(decimal(row.curLTV, `${label}.curLTV`));
    const marginCallLtv = Number(decimal(row.marginCallLTV, `${label}.marginCallLTV`));
    const liquidationLtv = Number(decimal(row.liqLTV, `${label}.liqLTV`));
    if (liquidationLtv <= 0 || marginCallLtv > liquidationLtv) {
      throw new Error(`${label} has invalid LTV thresholds`);
    }
    return {
      orderId,
      collateral: parseCoinAmounts(row.collateralData, `${label}.collateralData`),
      debts: parseCoinAmounts(row.loanData, `${label}.loanData`),
      adjustedCollateralUsd: decimal(row.collateralNotionalUsd, `${label}.collateralNotionalUsd`),
      debtUsd: decimal(row.loanNotionalUsd, `${label}.loanNotionalUsd`),
      currentLtv,
      marginCallLtv,
      liquidationLtv,
      liquidation: instrumentId === null || price === null ? null : {
        instrumentId,
        price: decimal(price, `${label}.liqPx`),
      },
    };
  });
  return { updatedAt: root.updatedAt, orders };
}

export function parseOkxFlexibleLoanRates(value: unknown): OkxLoanRates {
  return new Map(array(value, "OKX loan interest").map((value) => {
    const row = record(value, "OKX loan interest");
    return [string(row.orderId, "OKX loan interest.orderId"), parseRateHistory(row.history, "borrowing")];
  }));
}

export function getOkxLoanRisk(loan: OkxFlexibleLoan) {
  const { currentLtv, marginCallLtv, liquidationLtv } = loan;
  const debt = Number(loan.debtUsd);
  const state = currentLtv >= liquidationLtv ? "liquidation"
    : currentLtv >= marginCallLtv ? "warning" : "healthy";

  return {
    state,
    healthFactor: debt > 0 ? Number(loan.adjustedCollateralUsd) * liquidationLtv / debt : null,
    liquidationHeadroom: liquidationLtv - currentLtv,
  };
}

export async function getOkxSavings(): Promise<OkxSavings> {
  return parseOkxSavings(await okxInvoke("okx_get_savings"));
}

export async function getOkxFlexibleLoans(): Promise<OkxFlexibleLoans> {
  return parseOkxFlexibleLoans(await okxInvoke("okx_get_flexible_loans"));
}

export async function getOkxFlexibleLoanRates(orderIds: string[]): Promise<OkxLoanRates> {
  if (orderIds.length === 0) return new Map();
  const rates = parseOkxFlexibleLoanRates(await okxInvoke("okx_get_flexible_loan_interest", { orderIds }));
  if (orderIds.some((id) => !rates.has(id))) throw new Error("OKX loan interest response is missing an order");
  return rates;
}
